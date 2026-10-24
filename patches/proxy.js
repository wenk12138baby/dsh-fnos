#!/usr/bin/env node
// ============================================================
// deepseekharness fnOS 统一网关代理（修复版）
//
// 相对原版的两处关键修复：
//   A. 认证 cookie 不再强行注入到浏览器请求。
//      dsh 0.2.x 的浏览器 cookie 用 Host 头派生 authority 签名（无 Host 直接拒绝），
//      所以「用 Host=127.0.0.1:3080 换来的 cookie」一旦被注入到 Host=NAS-IP 的
//      同源请求里，签名必然不匹配 → /api 401 → 前端 RPC 全挂 → 白屏。
//      正确做法：先探测浏览器请求的 Host 是否被 dsh 的 /api 信任围栏接受
//      （loopback / 本机网卡 IP / --trusted-host），接受就原样转发（保留 Host 与
//      Origin，cookie 由浏览器自己发），不接受才回落到 loopback 身份转发 + 注入 cookie。
//   B. 构建标记 __vite__mapDeps 里的 "./assets/..."、"./vendor-..." 之类的相对字面量
//      被旧逻辑改成了 "<prefix>./assets/..."（拼接错误），必须按路径边界匹配，
//      并且同时处理 "./x" 与 "../x" 两种形式。
//
// 用法: node proxy.js <socketPath> <gatewayPrefix> <target> [logFile]
// ============================================================
const http = require("http");
const net = require("net");
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");

// C: content-encoding 解压/压缩（dsh webserver 按 Accept-Encoding 输出 gzip/br/deflate）
function inflate(buf, enc) {
  switch (enc) {
    case "br":
      return zlib.brotliDecompressSync(buf);
    case "deflate":
      return zlib.inflateSync(buf);
    case "gzip":
    case "x-gzip":
      return zlib.gunzipSync(buf);
    default:
      throw new Error(`unsupported content-encoding ${enc}`);
  }
}
function deflate(buf, enc) {
  switch (enc) {
    case "br":
      return zlib.brotliCompressSync(buf);
    case "deflate":
      return zlib.deflateSync(buf);
    case "gzip":
    case "x-gzip":
      return zlib.gzipSync(buf, { level: 1 });
    default:
      throw new Error(`unsupported content-encoding ${enc}`);
  }
}

const SOCKET_PATH = process.argv[2];
const GATEWAY_PREFIX = (process.argv[3] || "/app/deepseekharness").replace(/\/+$/, "");
const TARGET = process.argv[4] || "127.0.0.1:3080";
const [TARGET_HOST, TARGET_PORT] = TARGET.split(":");
const TARGET_PORT_NUM = parseInt(TARGET_PORT, 10);
const LOG_FILE = process.argv[5] ||
  (process.env.TRIM_PKGVAR ? path.join(process.env.TRIM_PKGVAR, "dsh.log") : null);

// 额外可信 authority（与该应用 cmd/main 里的 --trusted-host 保持一致；可用环境变量追加）
const EXTRA_TRUSTED = (process.env.DSH_PROXY_TRUSTED || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// 需要重写为带前缀的绝对路径（单一来源，供绝对 / 形式与相对 ./ 形式共用）
const ROUTE_PREFIXES = ["/assets/", "/plugins/", "/api/", "/favicon", "/manifest", "/icons/"];

// crypto.randomUUID polyfill：HTTP（非安全上下文）下浏览器不提供该 API。
const RANDOM_UUID_POLYFILL = `<script>
;(function () {
  var g = typeof globalThis !== "undefined" ? globalThis : window;
  var c = g.crypto;
  if (!c) { try { c = g.crypto = {}; } catch (e) { c = {}; } }
  if (typeof c.randomUUID !== "function" && typeof c.getRandomValues === "function") {
    c.randomUUID = function () {
      var b = c.getRandomValues(new Uint8Array(16));
      b[6] = (b[6] & 0x0f) | 0x40;
      b[8] = (b[8] & 0x3f) | 0x80;
      var h = "";
      for (var i = 0; i < 16; i++) {
        if (i === 4 || i === 6 || i === 8 || i === 10) h += "-";
        h += (b[i] < 16 ? "0" : "") + b[i].toString(16);
      }
      return h;
    };
  }
})();
</script>`;

// 转发时移除的浏览器标记头（仅在「回落为 loopback 身份」模式下移除）
const STRIP_HEADERS = new Set([
  "origin",
  "sec-fetch-site",
  "sec-fetch-mode",
  "sec-fetch-dest",
  "sec-fetch-user",
  "sec-ch-ua",
  "sec-ch-ua-mobile",
  "sec-ch-ua-platform",
  "sec-ch-ua-platform-version",
  "sec-ch-ua-full-version-list",
  "sec-ch-prefers-color-scheme",
  "sec-ch-viewport-width",
  "referer",
  "x-requested-with",
]);

// ------------------------------------------------------------
// Host 信任围栏镜像：只用于「是否需要回落身份」
// ------------------------------------------------------------
function isLoopbackHostname(hostname) {
  const h = (hostname || "").toLowerCase().replace(/^\[|\]$/g, "");
  if (h === "localhost" || h === "::1" || h === "0:0:0:0:0:0:0:1") return true;
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
  if (h === "::ffff:127.0.0.1") return true;
  return false;
}

// 本机所有非回环 IPv4（用于判定「浏览器是用 NAS 局域网 IP 访问的」）
function localAddresses() {
  try {
    const ifaces = require("os").networkInterfaces();
    const out = new Set();
    for (const list of Object.values(ifaces || {})) {
      for (const it of list || []) out.add(it.address);
    }
    return out;
  } catch (e) {
    return new Set();
  }
}
const LOCAL_ADDRS = localAddresses();

// Host 头是否被 dsh 的 /api 信任围栏接受
function hostAccepted(rawHost) {
  if (!rawHost) return false;
  const hostname = rawHost.replace(/:\d+$/, "").replace(/^\[|\]$/g, "").toLowerCase();
  if (isLoopbackHostname(hostname)) return true;
  if (nameIsLanIp(hostname) || LOCAL_ADDRS.has(hostname)) return true;
  if (EXTRA_TRUSTED.some((e) => e.toLowerCase() === rawHost.toLowerCase() || e.toLowerCase() === hostname)) return true;
  return false;
}

function nameIsLanIp(hostname) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
}

// ------------------------------------------------------------
// HTML / JS 响应体前缀改写
// ------------------------------------------------------------
function rewriteBody(body) {
  let out = body;

  // B: 构建标记里的相对字面量 "./assets/xxx"、"../assets/xxx"
  //    只有在路径边界（引号/括号/等号/反引号/空白/comma）出现时才添加前缀；
  //    注意新版 dsh 的前端「document-relative」引用 ./plugins/ 是刻意设计的，
  //    它们会随 <base href> 一起指向网关前缀，因此这里不能改写，只能改写
  //    ./assets 这类真正会随 base 生效的资源前缀。
  for (const p of ROUTE_PREFIXES) {
    // 绝对形式："/assets/、'/assets/、(/assets/、 /assets/、`/assets/、=/assets/
    out = out.split(`"${p}`).join(`"${GATEWAY_PREFIX}${p}`);
    out = out.split(`'${p}`).join(`'${GATEWAY_PREFIX}${p}`);
    out = out.split(`(${p}`).join(`(${GATEWAY_PREFIX}${p}`);
    out = out.split(` ${p}`).join(` ${GATEWAY_PREFIX}${p}`);
    out = out.split(`\`${p}`).join(`\`${GATEWAY_PREFIX}${p}`);
    out = out.split(`=${p}`).join(`=${GATEWAY_PREFIX}${p}`);

    // 相对形式："./assets/、'./assets/、(./assets/、 ./assets/、`./assets/
    // 注意 p 本身以 "/" 开头，所以相对写法是 "." + p（= "./assets/），
    // 模板必须写 `".${p}`，写成 `"./${p}` 会拼成 "./ /assets/" 而永远匹配不到。
    out = out.split(`".${p}`).join(`"${GATEWAY_PREFIX}${p}`);
    out = out.split(`'.${p}`).join(`'${GATEWAY_PREFIX}${p}`);
    out = out.split(`(.${p}`).join(`(${GATEWAY_PREFIX}${p}`);
    out = out.split(` .${p}`).join(` ${GATEWAY_PREFIX}${p}`);
    out = out.split(`\`.${p}`).join(`\`${GATEWAY_PREFIX}${p}`);
    out = out.split(`=${p}`).join(`=${GATEWAY_PREFIX}${p}`);
  }

  // 变量赋值形式的 /api 字面量（如 API_PATH = "/api"）加前缀
  out = out.replace(/(["'`])\/api(?=(["'`])|\/|\?)/g, `$1${GATEWAY_PREFIX}/api`);

  // 清理重复前缀
  out = out.split(`${GATEWAY_PREFIX}${GATEWAY_PREFIX}`).join(GATEWAY_PREFIX);

  // <base href> 指向网关前缀（飞牛 iframe 入口无尾斜杠，保留 ./ 会错位）
  out = out.replace(/<base href="\.\/">/g, `<base href="${GATEWAY_PREFIX}/">`);
  // 兜底：若 dsh 未注入 base，则自己补一个
  if (/<html/i.test(out) && !/<base\s/i.test(out)) {
    out = out.replace(/<head([^>]*)>/i, (m, attrs) => `<head${attrs}><base href="${GATEWAY_PREFIX}/">`);
  }

  // 注入 crypto.randomUUID polyfill
  if (/<html/i.test(out)) {
    out = out.replace(/<head([^>]*)>/i, (m, attrs) => `<head${attrs}>${RANDOM_UUID_POLYFILL}`);
  }
  return out;
}

function stripPrefix(pathname) {
  if (pathname === GATEWAY_PREFIX) return "/";
  if (pathname.startsWith(GATEWAY_PREFIX + "/")) {
    return pathname.slice(GATEWAY_PREFIX.length);
  }
  return pathname;
}

function splitUrl(u) {
  const qi = u.indexOf("?");
  if (qi < 0) return { pathname: u, query: "" };
  return { pathname: u.slice(0, qi), query: u.slice(qi + 1) };
}

function toTargetPath(u) {
  const { pathname, query } = splitUrl(u);
  return stripPrefix(pathname) + (query ? "?" + query : "");
}

// ------------------------------------------------------------
// 可选：launch token → loopback cookie（仅回落模式使用）
// ------------------------------------------------------------
let authCookie = null;
let authToken = null;

function readLaunchToken() {
  if (!LOG_FILE) return null;
  let data;
  try {
    data = fs.readFileSync(LOG_FILE, "utf8");
  } catch (e) {
    return null;
  }
  const re = /dsh web: https?:\/\/\S+?[?&]token=([A-Za-z0-9_-]+)/g;
  let m;
  let last = null;
  while ((m = re.exec(data)) !== null) last = m[1];
  return last;
}

function exchangeToken(token) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: TARGET_HOST,
        port: TARGET_PORT_NUM,
        method: "GET",
        path: `/?token=${encodeURIComponent(token)}`,
        headers: { host: `${TARGET_HOST}:${TARGET_PORT}` },
      },
      (res) => {
        res.resume();
        const sc = res.headers["set-cookie"];
        if (res.statusCode === 303 && Array.isArray(sc) && sc.length) {
          resolve(sc[0].split(";")[0]);
        } else {
          reject(new Error(`token exchange status=${res.statusCode}`));
        }
      }
    );
    req.on("error", reject);
    req.end();
  });
}

async function ensureAuth() {
  const token = readLaunchToken();
  if (!token) throw new Error("launch token not found in dsh log");
  if (authCookie && authToken === token) return authCookie;
  const cookie = await exchangeToken(token);
  authCookie = cookie;
  authToken = token;
  return cookie;
}

async function ensureAuthWithRetry(retries = 30, intervalMs = 2000) {
  let lastErr;
  for (let i = 0; i < retries; i++) {
    try {
      return await ensureAuth();
    } catch (e) {
      lastErr = e;
      await new Promise((r) => setTimeout(r, intervalMs));
    }
  }
  throw lastErr;
}

function logLine(msg) {
  try {
    if (LOG_FILE) fs.appendFileSync(LOG_FILE, `${new Date().toISOString()} - [proxy] ${msg}\n`);
  } catch (e) {}
}

// ------------------------------------------------------------
// 转发
// ------------------------------------------------------------
function passThroughHeaders(origHeaders) {
  const h = { ...origHeaders };
  h.connection = "close";
  return h;
}

function loopbackHeaders(origHeaders, cookie) {
  const h = { ...origHeaders };
  for (const name of STRIP_HEADERS) delete h[name];
  h.host = `${TARGET_HOST}:${TARGET_PORT}`;
  h.connection = "close";
  if (cookie) h.cookie = cookie;
  else delete h.cookie;
  return h;
}

const server = http.createServer(async (req, res) => {
  const targetPath = toTargetPath(req.url);
  const accepted = hostAccepted(req.headers.host);

  let headers;
  if (accepted) {
    headers = passThroughHeaders(req.headers);
  } else {
    let cookie = null;
    try {
      cookie = await ensureAuthWithRetry();
    } catch (e) {
      logLine(`loopback fallback auth failed: ${e.message}`);
    }
    headers = loopbackHeaders(req.headers, cookie);
  }

  const proxyReq = http.request(
    {
      host: TARGET_HOST,
      port: TARGET_PORT_NUM,
      method: req.method,
      path: targetPath,
      headers,
    },
    (proxyRes) => {
      const ctype = (proxyRes.headers["content-type"] || "").toString();
      const isText = /text\/|javascript|json|xml|webmanifest/.test(ctype);
      const enc = (proxyRes.headers["content-encoding"] || "").toString().toLowerCase();
      const compressed = enc !== "" && enc !== "identity";
      const chunks = [];
      proxyRes.on("data", (c) => chunks.push(c));
      proxyRes.on("end", () => {
        let body = Buffer.concat(chunks);
        if (isText && body.length < 20 * 1024 * 1024) {
          // C: dsh 会按 Accept-Encoding 输出 gzip（webserver compression: gzip），
          //    这里必须先解压 -> 改写 -> 重新按原编码压缩，否则把 gzip 字节流当
          //    UTF-8 文本处理会整段损坏 / 或改写被跳过（原版就跳过了，直接白屏）。
          try {
            const plain = compressed ? inflate(body, enc) : body.toString("utf8");
            const text = compressed ? plain.toString("utf8") : plain;
            const rewritten = rewriteBody(text);
            if (compressed) {
              body = deflate(Buffer.from(rewritten, "utf8"), enc);
            } else {
              body = Buffer.from(rewritten, "utf8");
            }
          } catch (e) {
            logLine(`rewrite skipped (${enc || "identity"}): ${e.message}`);
          }
        }
        const outHeaders = { ...proxyRes.headers };
        delete outHeaders["content-length"];
        // 静态资源不要被浏览器长期缓存，避免升级后拿到旧 bundle
        if (/\/assets\//.test(targetPath)) outHeaders["cache-control"] = "no-cache";
        res.writeHead(proxyRes.statusCode, outHeaders);
        res.end(body);
      });
    }
  );
  proxyReq.on("error", (e) => {
    try {
      res.writeHead(502, { "content-type": "text/plain; charset=utf-8" });
      res.end(`proxy error: ${e.message}`);
    } catch (err) {}
  });
  req.pipe(proxyReq);
});

// WebSocket / upgrade 透传
server.on("upgrade", async (req, socket, head) => {
  const targetPath = toTargetPath(req.url);
  const accepted = hostAccepted(req.headers.host);
  let headers;
  if (accepted) {
    headers = { ...req.headers };
    delete headers["connection"];
    delete headers["upgrade"];
    headers["connection"] = "Upgrade";
    headers["upgrade"] = req.headers["upgrade"] || "websocket";
  } else {
    let cookie = null;
    try {
      cookie = await ensureAuthWithRetry();
    } catch (e) {
      logLine(`ws loopback fallback auth failed: ${e.message}`);
    }
    headers = { ...req.headers };
    for (const name of STRIP_HEADERS) delete headers[name];
    headers.host = `${TARGET_HOST}:${TARGET_PORT}`;
    if (cookie) headers.cookie = cookie;
    else delete headers.cookie;
  }
  const proxySocket = net.connect(TARGET_PORT_NUM, TARGET_HOST, () => {
    proxySocket.write(
      `${req.method} ${targetPath} HTTP/1.1\r\n` +
        Object.entries(headers)
          .map(([k, v]) => `${k}: ${v}`)
          .join("\r\n") +
        "\r\n\r\n"
    );
    if (head && head.length) proxySocket.write(head);
  });
  proxySocket.on("error", () => socket.destroy());
  socket.on("error", () => proxySocket.destroy());
  socket.pipe(proxySocket);
  proxySocket.pipe(socket);
});

try {
  fs.unlinkSync(SOCKET_PATH);
} catch (e) {}

server.listen(SOCKET_PATH, () => {
  try {
    fs.chmodSync(SOCKET_PATH, 0o777);
  } catch (e) {}
  console.log(`dsh gateway proxy listening on ${SOCKET_PATH} (prefix=${GATEWAY_PREFIX}, target=${TARGET})`);
});
