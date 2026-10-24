#!/usr/bin/env node
/**
 * DeepSeek Harness — fnOS 网关反向代理
 * ============================================================================
 *
 * 职责
 * ----
 * 1. 作为父进程启动 DSH Web，绑到**内部端口**（不对外）
 * 2. 从它的 stdout 里抓出 launch token（形如 `?token=...`）
 * 3. 同时监听两条入口：
 *    a) fnOS 统一网关要求的 unix socket（`target/app.sock`）
 *    b) manifest.service_port 声明的 TCP 端口（fnOS 桌面 iframe 可能直连它）
 * 4. 把请求剥掉 `/app/DeepSeekHarness` 前缀（若有），转给 DSH 内部端口
 * 5. 首次访问时 302 到带 token 的地址，让 DSH 种下认证 cookie
 *
 * 为什么必须双监听
 * ----------------
 * fnOS 打开 iframe 时可能走统一网关（socket），也可能因为 manifest 里声明了
 * `service_port` 而直接连该端口。如果只有 socket，端口那条路会打到 DSH 本身，
 * 而 DSH 要求先拿 launch token，于是浏览器看到的是它自己的 401：
 *   "dsh web authentication required; reopen the URL printed by dsh web."
 * 两条路都指向本代理，才不会漏掉任何一种打开方式。
 *
 * 为什么要改写 Host / Origin
 * -------------------------
 * DSH 的 `/api` 信任围栏（dsh-client-connection isTrustedApiRequest）只放行：
 *   - loopback 主机名
 *   - 监听器自身绑定的 IP
 *   - --trusted-host 白名单
 * 并且当请求带 Origin 头时，要求 Origin 与 Host 同源。
 *
 * 网关/端口转发来的 Host 是 NAS 的访问域名（如 nas.local:5666），Origin 也是它。
 * 若原样转发会被判 403。这里统一把 Host 改写成 127.0.0.1:DSH_PORT（loopback，
 * 第一关直接过），并删除 Origin（第二关 `origin === undefined` 直接放行）。
 * 这样无需在安装时知道 NAS 域名/IP，换地址也不用改配置。
 *
 * 认证语义
 * --------
 * DSH 的 cookie authority 由 Host 头算出，固定为 `127.0.0.1:DSH_PORT`，因此
 *   - cookie 名稳定，不随 NAS 域名变化
 *   - 换域名/换 IP 后已登录的浏览器仍然有效
 * 代价是所有 fnOS 用户共享同一个 launch token（见 README 的「已知边界」）。
 *
 * 管理员校验
 * ----------
 * 走网关时 fnOS 会注入 X-Trim-Isadmin，此时强制校验管理员身份。
 * 走端口直连时没有这些头（fnOS 不注入），无法判定身份，只能放行——这正是
 * 为什么本应用默认 `allUsers: false` 仅管理员可见，且建议在 fnOS 防火墙层
 * 限制该端口的访问来源。相关权衡写在 README 的「安全边界」。
 */

import http from 'node:http'
import net from 'node:net'
import { spawn } from 'node:child_process'
import { createWriteStream, existsSync, mkdirSync, unlinkSync, chmodSync } from 'node:fs'
import path from 'node:path'

// ─────────────────────────────────────────────────────────────── 配置解析

const env = process.env
const APPDEST = env.TRIM_APPDEST || path.resolve(import.meta.dirname, '..')
const PKGVAR = env.TRIM_PKGVAR || path.join(APPDEST, '..', 'var')
const PKGHOME = env.TRIM_PKGHOME || path.join(APPDEST, '..', 'home')

/** 网关公开路径前缀，必须与 app/ui/config 的 gatewayPrefix 一致。 */
const PREFIX = env.GATEWAY_PREFIX || '/app/DeepSeekHarness'

/**
 * 对外监听端口（= manifest.service_port，经 TRIM_SERVICE_PORT 注入）。
 * 反代占这个端口，DSH 退到内部端口，避免 fnOS 直连时绕过反代。
 */
const LISTEN_PORT = Number(env.TRIM_SERVICE_PORT || 3080)
const LISTEN_HOST = env.GATEWAY_LISTEN_HOST || '0.0.0.0'

/**
 * DSH 内部端口：默认取对外端口 +10000，超出范围则 -10000。
 * 这样既不与对外端口冲突，也不占用常见服务端口。
 * 本地调试可用 DSH_INTERNAL_PORT 覆盖。
 */
const DSH_PORT = Number(
  env.DSH_INTERNAL_PORT ||
    (LISTEN_PORT + 10000 <= 65535 ? LISTEN_PORT + 10000 : LISTEN_PORT - 10000),
)
const DSH_HOST = '127.0.0.1'

/** 网关 socket 必须位于 target 目录下（fnOS 约定）。 */
const SOCKET_PATH = env.GATEWAY_SOCKET_PATH || path.join(APPDEST, 'app.sock')

/** 是否启用网关 socket 监听。本地调试可设 GATEWAY_SOCKET=0 只开 TCP。 */
const ENABLE_SOCKET = env.GATEWAY_SOCKET !== '0'

/** 是否启用 TCP 端口监听。本地调试可设 GATEWAY_TCP=0 只开 socket。 */
const ENABLE_TCP = env.GATEWAY_TCP !== '0'

/** 是否强制管理员访问。默认开启；本地调试设 ENFORCE_ADMIN=0 关闭。 */
const ENFORCE_ADMIN = env.ENFORCE_ADMIN !== '0'

/**
 * 拉起 DSH 子进程用的 Node。
 *
 * 默认复用当前进程的 Node（process.execPath）：网关自己就是被 detect-node.sh
 * 挑出来的那个 Node 启动的，特性已经验证过，没必要再探一次，也不可能选到
 * 不同版本。DSH_NODE_BIN 仅用于本地调试时强制指定。
 */
const NODE_BIN = env.DSH_NODE_BIN || process.execPath
const DSH_BIN = env.DSH_BIN || path.join(APPDEST, 'dsh', 'node_modules', '@deepseek-ai', 'dsh', 'lib', 'bin.js')
const DSH_CWD = env.DSH_CWD || path.join(APPDEST, 'dsh')

const READY_TIMEOUT_MS = Number(env.DSH_READY_TIMEOUT_MS || 180_000)
const TOKEN_PATTERN = /[?&]token=([A-Za-z0-9_-]+)/

// ─────────────────────────────────────────────────────────────── 日志

mkdirSync(PKGVAR, { recursive: true })

/**
 * 日志只写一个地方。
 *
 * 之前同时写 logStream（gateway.log）和 process.stdout，而 cmd/main 用
 * `>> gateway.log` 把 stdout 也重定向到同一个文件 —— 两个独立的文件描述符
 * 各自维护写入偏移，结果每行都出现两遍，且偶尔交错。
 *
 * 现在只在「stdout 不是文件」时才往 stdout 写（手动前台运行调试的场景），
 * 其余情况一律只写文件，由 lifecycle 脚本的 2>&1 负责捕获意外输出。
 */
const logStream = createWriteStream(path.join(PKGVAR, 'gateway.log'), { flags: 'a' })

function log(level, message) {
  const line = `[${new Date().toISOString()}] [${level}] ${message}\n`
  logStream.write(line)
  // 手动前台运行（stdout 是终端）时也回显一份，方便排查；
  // 被 lifecycle 脚本重定向到日志文件时不回显，避免双写。
  if (process.stdout.isTTY === true) process.stdout.write(line)
}

/** 生命周期脚本失败时，把可读原因写进 fnOS 的用户可见日志。 */
function failLoud(message) {
  log('ERROR', message)
  const target = env.TRIM_TEMP_LOGFILE
  if (target) {
    try {
      createWriteStream(target, { flags: 'a' }).end(`DeepSeek Harness: ${message}\n`)
    } catch {
      /* 日志文件不可写时只保留进程日志 */
    }
  }
}

// ─────────────────────────────────────────────────────────────── 启动 DSH

let launchToken
let child

function spawnDsh() {
  const args = [
    DSH_BIN,
    '--profile', 'web',
    '--host', DSH_HOST,
    '--port', String(DSH_PORT),
    '--no-open',
  ]

  mkdirSync(path.join(PKGVAR, 'tmp'), { recursive: true })

  log('INFO', `spawning dsh: ${NODE_BIN} ${args.join(' ')}`)

  child = spawn(NODE_BIN, args, {
    cwd: DSH_CWD,
    env: {
      ...env,
      DSH_HOME: PKGHOME,
      // npm / pnpm 需要可写的 HOME 存放缓存（~/.npm、~/.cache）。
      // fnOS 的包用户没有真实家目录（/home/deepseek-harness 不存在），
      // 不设这一项会让插件市场报 EACCES mkdir /home/<user>。
      HOME: PKGHOME,
      // fnOS 应用目录通常是只读挂载点，Node 的编译缓存与临时文件必须落可写目录。
      TMPDIR: path.join(PKGVAR, 'tmp'),
      NO_COLOR: '1',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  })

  child.stdout.setEncoding('utf8')
  child.stdout.on('data', (chunk) => {
    logStream.write(chunk)
    if (launchToken === undefined) {
      const match = TOKEN_PATTERN.exec(chunk)
      if (match) {
        launchToken = match[1]
        log('INFO', 'launch token captured')
        startServers()
      }
    }
  })

  child.stderr.setEncoding('utf8')
  child.stderr.on('data', (chunk) => {
    logStream.write(chunk)
    // 启动期错误直接转述给用户可见日志，避免只留在 gateway.log 里
    if (!/^\s*$/.test(chunk) && launchToken === undefined) process.stderr.write(chunk)
  })

  child.on('exit', (code, signal) => {
    log('WARN', `dsh exited: code=${code} signal=${signal}`)
    if (launchToken === undefined) {
      failLoud(`dsh 启动失败（退出码 ${code}），详见 ${path.join(PKGVAR, 'gateway.log')}`)
    }
    shutdown(code ?? 1)
  })

  child.on('error', (error) => {
    failLoud(`无法启动 dsh: ${error.message}`)
    shutdown(1)
  })

  setTimeout(() => {
    if (launchToken === undefined) {
      failLoud(`dsh 在 ${READY_TIMEOUT_MS}ms 内未就绪`)
      shutdown(1)
    }
  }, READY_TIMEOUT_MS).unref()
}

// ─────────────────────────────────────────────────────────────── HTTP 转发

/** 逐跳头与需要改写的头，不参与转发。 */
const STRIP_HEADERS = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
])

/** 剥掉网关前缀，保留查询串。 */
function stripPrefix(url) {
  const queryAt = url.indexOf('?')
  const pathname = queryAt === -1 ? url : url.slice(0, queryAt)
  const query = queryAt === -1 ? '' : url.slice(queryAt)

  if (pathname === PREFIX) return '/' + query
  if (pathname.startsWith(PREFIX + '/')) return pathname.slice(PREFIX.length) + query
  // 网关若已剥掉前缀，或请求来自端口直连，原样使用
  return url
}

/** 组装转发头：改 Host、删 Origin，其余透传。 */
function forwardHeaders(req) {
  const headers = {}
  for (const [name, value] of Object.entries(req.headers)) {
    const lower = name.toLowerCase()
    if (STRIP_HEADERS.has(lower)) continue
    if (lower === 'host') continue
    // DSH 的 Origin 围栏要求 Origin 与 Host 同源；Host 被改写后原 Origin 必然不匹配。
    if (lower === 'origin') continue
    headers[lower] = value
  }
  headers.host = `${DSH_HOST}:${DSH_PORT}`
  return headers
}

/**
 * 浏览器是否已持有 DSH 会话 cookie。
 * 实测 DSH 的 cookie 名形如 `dsh-auth-<base64url(sha256(authority))>`，值以 `v1.` 开头。
 */
function hasDshCookie(req) {
  const cookie = req.headers.cookie
  if (cookie === undefined) return false
  return /(?:^|;\s*)dsh-auth-[A-Za-z0-9_-]+=/.test(cookie)
}

/** 请求是否带网关注入的身份头。 */
function hasTrimIdentity(req) {
  return req.headers['x-trim-isadmin'] !== undefined
}

/** 管理员校验：网关会注入 X-Trim-Isadmin。 */
function isAdmin(req) {
  return req.headers['x-trim-isadmin'] === 'true'
}

/**
 * 首次访问时跳转的目标。
 *
 * DSH 只在 pathname === "/" 时接受 token 换 cookie，所以剥前缀后必须是根。
 * 跳转路径要跟请求来源保持同一形态：
 *   - 走网关（/app/DeepSeekHarness/...）→ 跳到 /app/DeepSeekHarness/?token=
 *   - 走端口（/...）→ 跳到 /?token=
 * 否则直连场景会跳到不存在的带前缀路径，或网关场景丢了前缀导致 404。
 */
function loginRedirectPath(originalUrl) {
  const pathname = originalUrl.split('?')[0]
  const prefixed = pathname === PREFIX || pathname.startsWith(PREFIX + '/')
  return prefixed ? `${PREFIX}/?token=${launchToken}` : `/?token=${launchToken}`
}

function handleRequest(req, res) {
  const originalUrl = req.url || '/'

  // 网关来的请求带身份头，强制管理员；端口直连没有这些头，只能放行。
  if (ENFORCE_ADMIN && hasTrimIdentity(req) && !isAdmin(req)) {
    res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' })
    res.end('DeepSeek Harness 仅限管理员访问。请使用管理员账号登录飞牛 fnOS。\n')
    return
  }

  const targetPath = stripPrefix(originalUrl)

  // 首次访问：没有 DSH cookie 也没有 token 时，302 到带 token 的地址。
  if (!hasDshCookie(req) && !/[?&]token=/.test(targetPath)) {
    res.writeHead(302, {
      location: loginRedirectPath(originalUrl),
      'cache-control': 'no-store',
      'referrer-policy': 'no-referrer',
    })
    res.end()
    return
  }

  const proxyReq = http.request(
    { host: DSH_HOST, port: DSH_PORT, method: req.method, path: targetPath, headers: forwardHeaders(req) },
    (proxyRes) => {
      res.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers)
      proxyRes.pipe(res)
    },
  )

  proxyReq.on('error', (error) => {
    log('ERROR', `proxy request failed: ${error.message}`)
    if (!res.headersSent) {
      res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' })
      res.end('DeepSeek Harness 服务未就绪，请稍后重试。\n')
    } else {
      res.end()
    }
  })

  req.pipe(proxyReq)
}

// ─────────────────────────────────────────────────────────────── WebSocket 升级

function handleUpgrade(req, socket, head) {
  const originalUrl = req.url || '/'

  if (ENFORCE_ADMIN && hasTrimIdentity(req) && !isAdmin(req)) {
    socket.end('HTTP/1.1 403 Forbidden\r\n\r\n')
    return
  }

  const targetPath = stripPrefix(originalUrl)
  const headers = forwardHeaders(req)
  headers.connection = 'Upgrade'
  headers.upgrade = req.headers.upgrade || 'websocket'

  const upstream = net.connect(DSH_PORT, DSH_HOST, () => {
    const lines = [`GET ${targetPath} HTTP/1.1`]
    for (const [name, value] of Object.entries(headers)) {
      if (Array.isArray(value)) for (const item of value) lines.push(`${name}: ${item}`)
      else if (value !== undefined) lines.push(`${name}: ${value}`)
    }
    upstream.write(lines.join('\r\n') + '\r\n\r\n')
    if (head && head.length > 0) upstream.write(head)
    upstream.pipe(socket)
    socket.pipe(upstream)
  })

  upstream.on('error', (error) => {
    log('ERROR', `websocket upstream failed: ${error.message}`)
    socket.destroy()
  })
  socket.on('error', () => upstream.destroy())
}

// ─────────────────────────────────────────────────────────────── 服务监听

/** 已建立的监听器，退出时统一关闭。 */
const listeners = []
let started = false

/** 创建一个 HTTP 服务实例（socket 与 TCP 各一份，互不影响）。 */
function createServer(label) {
  const server = http.createServer(handleRequest)
  server.on('upgrade', handleUpgrade)
  server.on('clientError', (_error, socket) => socket.destroy())
  server.on('error', (error) => {
    // 单条通道失败不能拖垮另一条：socket 建不起来时 TCP 往往仍然可用，
    // 反之亦然。全部失败才算致命（在 startServers 里判断）。
    log('ERROR', `${label} 监听失败: ${error.message}`)
    const record = listeners.find((item) => item.server === server)
    if (record) record.failed = true
    checkAllFailed()
  })
  return server
}

/** 所有通道都失败时才退出；只要还有一条活着就继续服务。 */
function checkAllFailed() {
  if (listeners.length === 0) return
  if (listeners.some((item) => !item.failed)) return
  failLoud('所有监听通道都启动失败，详见 gateway.log')
  shutdown(1)
}

function startServers() {
  if (started) return
  started = true

  if (ENABLE_SOCKET) {
    if (existsSync(SOCKET_PATH)) {
      try {
        unlinkSync(SOCKET_PATH)
      } catch (error) {
        log('WARN', `could not remove stale socket: ${error.message}`)
      }
    }
    const socketServer = createServer('unix socket')
    listeners.push({ kind: 'socket', server: socketServer, failed: false })
    socketServer.listen(SOCKET_PATH, () => {
      try {
        // fnOS 的网关进程需要能连上它；0666 在应用私有目录内是可接受的。
        chmodSync(SOCKET_PATH, 0o666)
      } catch (error) {
        log('WARN', `could not chmod socket: ${error.message}`)
      }
      log('INFO', `listening on unix:${SOCKET_PATH} -> ${DSH_HOST}:${DSH_PORT}`)
    })
  }

  if (ENABLE_TCP) {
    const tcpServer = createServer('tcp')
    listeners.push({ kind: 'tcp', server: tcpServer, failed: false })
    tcpServer.listen(LISTEN_PORT, LISTEN_HOST, () => {
      log('INFO', `listening on tcp://${LISTEN_HOST}:${LISTEN_PORT} -> ${DSH_HOST}:${DSH_PORT}`)
    })
  }

  if (listeners.length === 0) {
    failLoud('没有任何监听通道被启用（GATEWAY_SOCKET=0 且 GATEWAY_TCP=0）')
    shutdown(1)
  }
}

// ─────────────────────────────────────────────────────────────── 退出

let shuttingDown = false

function shutdown(code) {
  if (shuttingDown) return
  shuttingDown = true
  log('INFO', `shutting down (code ${code})`)

  for (const { server } of listeners) {
    try {
      server.close()
    } catch {
      /* 关闭失败不影响退出 */
    }
  }

  const finish = () => {
    if (ENABLE_SOCKET && existsSync(SOCKET_PATH)) {
      try {
        unlinkSync(SOCKET_PATH)
      } catch {
        /* 退出清理失败不影响进程终止 */
      }
    }
    logStream.end()
    process.exit(code)
  }

  if (child && child.exitCode === null) {
    child.kill('SIGTERM')
    setTimeout(() => {
      if (child.exitCode === null) child.kill('SIGKILL')
      finish()
    }, 5000).unref()
  } else {
    finish()
  }
}

process.on('SIGTERM', () => shutdown(0))
process.on('SIGINT', () => shutdown(0))
process.on('uncaughtException', (error) => {
  failLoud(`未捕获异常: ${error?.stack || error}`)
  shutdown(1)
})

// ─────────────────────────────────────────────────────────────── 主流程

log(
  'INFO',
  `starting: appdest=${APPDEST} home=${PKGHOME} var=${PKGVAR} ` +
    `prefix=${PREFIX} listen=${ENABLE_TCP ? LISTEN_HOST + ':' + LISTEN_PORT : '-'} ` +
    `socket=${ENABLE_SOCKET ? SOCKET_PATH : '-'} dsh=127.0.0.1:${DSH_PORT}`,
)
spawnDsh()
