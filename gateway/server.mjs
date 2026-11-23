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
import { createWriteStream, existsSync, mkdirSync, unlinkSync, chmodSync, readFileSync, writeFileSync } from 'node:fs'
import zlib from 'node:zlib'
import { randomBytes, timingSafeEqual } from 'node:crypto'
import path from 'node:path'

/** base64url 字符集，用于校验令牌形态。 */
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/

// ─────────────────────────────────────────────────────────────── 配置解析

const env = process.env
const APPDEST = env.TRIM_APPDEST || path.resolve(import.meta.dirname, '..')

/**
 * var / home 的解析顺序很重要：
 *   1. fnOS 注入的 TRIM_* 最可信；
 *   2. 其次是 cmd/main 已经算好并导出的 DSH_PKGVAR / DSH_HOME（它会顺着
 *      /var/apps/<app>/home 软链解析到真实存储路径）；
 *   3. 最后才是按 APPDEST 上一级推算 —— 注意这条路在 TRIM_APPDEST 为
 *      @appcenter/<app> 时会落到 <vol>/@appcenter/home，那是一个全空的新目录
 *      （会话读不到、插件不加载、登录直接 401）。
 *   所以 DSH_* 必须排在默认推算之前。gw_home_env_v1
 */
const PKGVAR = env.TRIM_PKGVAR || env.DSH_PKGVAR || path.join(APPDEST, '..', 'var')
const PKGHOME = env.TRIM_PKGHOME || env.DSH_HOME || path.join(APPDEST, '..', 'home')

/** 网关公开路径前缀，必须与 app/ui/config 的 gatewayPrefix 一致。 */
const PREFIX = env.GATEWAY_PREFIX || '/app/DeepSeekHarness'

/**
 * 对外监听端口（= manifest.service_port，经 TRIM_SERVICE_PORT 注入）。
 * 反代占这个端口，DSH 退到内部端口，避免 fnOS 直连时绕过反代。
 */
const LISTEN_PORT = Number(env.DSH_SERVICE_PORT || env.TRIM_SERVICE_PORT || 3080)
const LISTEN_HOST = env.GATEWAY_LISTEN_HOST || '0.0.0.0'

/**
 * DSH 内部端口。
 *
 * 优先用 cmd/main 探测好并导出的 DSH_INTERNAL_PORT —— 生命周期脚本会
 * 先挑一个确认空闲的端口，这里直接用，不要再自己算一遍。
 *
 * 旧实现写死「对外端口 ±10000」。这个推导在 13080 被别的应用占用时是死局：
 * 用户即便在设置里改了对外端口，内部端口仍可能撞车，且错误信息只说
 * 「内部端口被占用」，用户无法自救。现在改为端口池探测。
 *
 * 只有在脱离 cmd/main 手动调试（没走探测）时才退回 ±10000 的推导。
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

/**
 * 选一个真正可写的临时目录。
 *
 * 顺序：环境变量 TMPDIR > ${PKGVAR}/tmp > 系统 /tmp
 * 每个候选都实际写一个探针文件验证，不靠推测。
 *
 * 为什么不能省掉探测：
 * DSH 的 spill 组件在 TMPDIR 下 mkdtemp，权限不对就 EACCES。而这类错误在
 * 界面上表现为「新建会话没反应」或「工具调用卡住」，用户完全无法自查。
 * 探测成本是一次 open/unlink，可以忽略。
 */
function resolveWritableTmpdir() {
  const candidates = []
  if (typeof env.TMPDIR === 'string' && env.TMPDIR !== '') candidates.push(env.TMPDIR)
  candidates.push(path.join(PKGVAR, 'tmp'))
  candidates.push('/tmp')

  for (const dir of candidates) {
    try {
      mkdirSync(dir, { recursive: true, mode: 0o700 })
      const probe = path.join(dir, `.dsh-probe-${process.pid}-${Date.now()}`)
      writeFileSync(probe, 'ok')
      unlinkSync(probe)
      if (dir !== candidates[0]) {
        log('WARN', `TMPDIR 回退到可用目录: ${dir}（首选 ${candidates[0]} 不可写）`)
      }
      return dir
    } catch {
      // 换下一个候选
    }
  }
  // 全都不行时的最后兜底：交给 OS，让错误在真正使用处暴露，而不是启动即崩。
  log('ERROR', '所有候选 TMPDIR 均不可写，退回系统默认')
  return undefined
}

// ─────────────────────────────────────────────────────────────── 崩溃重启策略

/** 重启前等待时间。2 秒足够让端口释放，又不会让用户觉得卡住。 */
const RESTART_DELAY_MS = 2000

/** 限流窗口与次数：窗口内崩溃太频繁说明是配置错误，不该无限重试。 */
const RESTART_WINDOW_MS = 5 * 60 * 1000
const RESTART_MAX = 3
let restartTimes = []

/**
 * 这次退出是否值得重启。
 *
 * 判据：
 *   - 正常退出（code 0）不重启，那是用户主动停用；
 *   - 5 分钟内已经崩过 3 次就不再重启 —— 大概率是配置问题，
 *     无限重启只会刷日志、掩盖真正的错误。
 */
function shouldRestart(code) {
  if (code === 0) return false
  const now = Date.now()
  restartTimes = restartTimes.filter((t) => now - t < RESTART_WINDOW_MS)
  if (restartTimes.length >= RESTART_MAX) {
    log('ERROR', `5 分钟内已崩溃 ${RESTART_MAX} 次，停止自动重启（请查看日志排查）`)
    return false
  }
  restartTimes.push(now)
  return true
}

// ─────────────────────────────────────────────────────────────── 启动 DSH

let launchToken
let child

/**
 * 读取固定 launch token。
 *
 * DSH 启动时会把随机 token 打印到 stdout，重启后已保存的访问链接就失效。
 * 从 launch-token.env 读取固定值后注入子进程环境，让 DSH 始终使用同一个
 * token —— 这样网关可以在「用户没有 cookie」时自动完成 token 交换，
 * 用户永远不需要看到 ?token=。
 *
 * 文件由 cmd/install_callback 生成；升级时会主动轮换（见 upgrade_init）。
 */
function readPinnedLaunchToken() {
  const file = path.join(PKGVAR, 'launch-token.env')
  if (!existsSync(file)) return {}
  try {
    const raw = readFileSync(file, 'utf8')
    for (const line of raw.split('\n')) {
      const trimmed = line.trim()
      if (trimmed === '' || trimmed.startsWith('#')) continue
      const eq = trimmed.indexOf('=')
      if (eq <= 0) continue
      const key = trimmed.slice(0, eq).trim()
      const value = trimmed
        .slice(eq + 1)
        .trim()
        .replace(/^['"]|['"]$/g, '')
      if (key === 'DSH_LAUNCH_TOKEN' && value !== '') return { DSH_LAUNCH_TOKEN: value }
    }
  } catch (error) {
    log('WARN', `readPinnedLaunchToken: ${error.message}`)
  }
  return {}
}

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
      // 临时目录必须真正可写。
      //
      // DSH 的 dsh-spill-local 会在 TMPDIR 下 mkdtemp 建私有溢出目录，
      // 官方源码默认直接交给 OS（不预设 TMPDIR），也就是假定它一定可写。
      // 之前无条件指向 ${PKGVAR}/tmp，在某些机器上该目录权限不对
      // （drw------- 或属主错位）就会 EACCES，表现为新建会话失败、
      // 长工具输出溢出不可用 —— 而且报错被吞掉，用户只看到「卡住了」。
      //
      // 这里先探测再决定，探测失败退回系统 /tmp，保证功能可用。
      TMPDIR: resolveWritableTmpdir(),
      NO_COLOR: '1',
      // 固定 launch token：让「点开即登录」在重启后依然有效。
      ...readPinnedLaunchToken(),
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
    const wasReady = launchToken !== undefined
    if (!wasReady) {
      failLoud(`dsh 启动失败（退出码 ${code}），详见 ${path.join(PKGVAR, 'gateway.log')}`)
    }
    // 已经就绪过还退出 = 运行期崩溃（典型是 OOM）。
    // 官方设计里重启是托管方的责任，飞牛应用中心不会管这件事，
    // 所以这里自己拉起来；否则用户会看到「应用运行中」但页面白屏，
    // 只能手动停用再启用 —— 普通用户根本不会这么自救。
    if (wasReady && shouldRestart(code) && !shuttingDown) {
      log('INFO', `dsh 异常退出，${RESTART_DELAY_MS / 1000}s 后自动重启`)
      setTimeout(() => {
        if (shuttingDown) return
        launchToken = undefined
        try {
          spawnDsh()
        } catch (error) {
          failLoud(`重启失败: ${error?.message ?? error}`)
          shutdown(1)
        }
      }, RESTART_DELAY_MS).unref()
      return
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

/**
 * 请求是否来自飞牛桌面（统一网关）。
 *
 * 判定方式刻意做得宽松：只要带**任何一个** `X-Trim-*` 头就算来自桌面。
 *
 * 为什么不只认 `x-trim-isadmin`：
 * 这些头是 /usr/trim/bin/trim_open_gateway 在应用层注入的，二进制里查不到
 * 确切的字段名，nginx 配置里也只设了 Host 与 X-Forwarded-Proto。如果只认
 * 单一头名而实际注入的是别的名字，桌面窗口会被自己的门禁挡在外面——用户
 * 看到的就是「应用打不开」。宁可认宽一点，也不能把正门堵死。
 *
 * 直连端口的浏览器请求不会带这些头（它们由 fnOS 网关按登录态生成），
 * 所以这个判据在方向上是对的。
 */
function hasTrimIdentity(req) {
  for (const name of Object.keys(req.headers)) {
    if (name.startsWith('x-trim-')) return true
  }
  return false
}

/**
 * 这个请求是否由飞牛**统一网关**转发而来（= 来自飞牛桌面）。
 *
 * 判据：必须同时具备
 *   1. 走 unix socket 通道 —— 网关只能通过 socket 转发，外部网络连不进来；
 *   2. 带 X-Trim-Userid 头 —— 由飞牛在转发前注入。
 *
 * 为什么要两个条件一起看：
 *   - 只看 socket 不够：实测发现从端口直连的桌面访问会让用户看到「需要授权」
 *     （见 app-entry 文档：端口服务与登录态无关）。所以 socket 只能作为
 *     「网关确实转发过」的佐证，不能单独当门禁。
 *   - 只看头不够：局域网直连者可以自己加 `X-Trim-Isadmin: true`（已实测能过）。
 *     但外部无法连到应用的私有 socket，因此「socket + 头」两者叠加才可信。
 *
 * 注意 X-Trim-Userid 而不是 X-Trim-Isadmin：
 * 前者是身份标识，桌面/普通用户都会有；后者只对管理员有值。
 */
function isGatewayForwarded(req) {
  if (req.__dshChannel !== 'socket') return false
  const uid = req.headers['x-trim-userid']
  return typeof uid === 'string' && uid.trim() !== ''
}

/** 管理员校验：网关会注入 X-Trim-Isadmin。 */
function isAdmin(req) {
  return req.headers['x-trim-isadmin'] === 'true'
}

// ─────────────────────────────────────────────── 局域网访问令牌（30 天）
//
// 为什么需要：
// 加严门禁后，只有飞牛桌面能进；但用户经常需要手机、另一台电脑、或把链接
// 发给同事临时看一眼。没有令牌就只能开 SSH 去改配置，这不是普通用户能做的。
//
// 设计取舍：
//   - 有效期 30 天：够长，不用天天重新生成；又不至于永久留着。
//   - 落盘在 @appdata，重启不失效。
//   - 在桌面窗口里可见可复制（用户明确要求），不藏在日志里。
//   - 校验用 timingSafeEqual，避免时序侧信道。
//
// 这个令牌等价于「已登录的浏览器会话」，所以必须是长随机串，且只发给
// 确实能打开飞牛桌面的人。
const ACCESS_TOKEN_DAYS = 30
const ACCESS_TOKEN_FILE = path.join(PKGVAR, 'access-token.env')

let accessToken
let accessTokenExpiresAt

/** 生成/读取 30 天访问令牌。首次调用时创建并落盘。 */
function loadOrCreateAccessToken() {
  if (accessToken !== undefined && accessTokenExpiresAt !== undefined && Date.now() < accessTokenExpiresAt) {
    return
  }
  // 先尝试读取已有令牌
  if (existsSync(ACCESS_TOKEN_FILE)) {
    try {
      const raw = readFileSync(ACCESS_TOKEN_FILE, 'utf8')
      if (raw.trim() !== '') {
        const parsed = JSON.parse(raw)
        if (
          typeof parsed?.token === 'string' &&
          BASE64URL_PATTERN.test(parsed.token) &&
          typeof parsed?.expiresAt === 'number' &&
          parsed.expiresAt > Date.now()
        ) {
          accessToken = parsed.token
          accessTokenExpiresAt = parsed.expiresAt
          return
        }
      }
    } catch (error) {
      log('WARN', `access-token.env 读取失败，将重新生成: ${error.message}`)
    }
  }
  // 生成新令牌
  const token = randomBytes(32).toString('base64url')
  const expiresAt = Date.now() + ACCESS_TOKEN_DAYS * 24 * 60 * 60 * 1000
  accessToken = token
  accessTokenExpiresAt = expiresAt
  try {
    const body = JSON.stringify({ token, expiresAt, createdAt: Date.now() }, null, 2)
    writeFileSync(ACCESS_TOKEN_FILE, body + '\n', { mode: 0o600 })
  } catch (error) {
    log('WARN', `access-token.env 写入失败: ${error.message}`)
  }
}

/** 常量时间比较，避免通过响应时间猜令牌。 */
function tokensEqual(a, b) {
  const ab = Buffer.from(String(a), 'utf8')
  const bb = Buffer.from(String(b), 'utf8')
  if (ab.length !== bb.length) return false
  return timingSafeEqual(ab, bb)
}

/**
 * 这个请求是否持有效的局域网访问令牌。
 *
 * 支持三种携带方式，方便用户直接用浏览器打开：
 *   ?access_token=xxx      显式查询参数
 *   #access_token=xxx      前端 hash（不会发到服务器，这里用不到，留作说明）
 *   Cookie: dsh-access=xxx 落地后自动记住，后续请求不必再带
 */
function hasValidAccessToken(req, url) {
  loadOrCreateAccessToken()
  if (accessToken === undefined || accessTokenExpiresAt === undefined || Date.now() >= accessTokenExpiresAt) {
    return false
  }
  const fromQuery = url.searchParams.get('access_token')
  if (fromQuery !== null && tokensEqual(fromQuery, accessToken)) return true

  const cookie = req.headers.cookie
  if (cookie !== undefined) {
    const match = /(?:^|;\s*)dsh-access=([A-Za-z0-9_-]+)/.exec(cookie)
    if (match !== null && tokensEqual(match[1], accessToken)) return true
  }
  return false
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

/**
 * 这个 401 是否值得用 token 流程重试。
 *
 * 只处理「文档类请求」：浏览器地址栏 / iframe 打开的页面。
 * 静态资源（.js/.css）和 XHR/fetch 拿到 401 时不能重定向，否则会把
 * 资源请求变成 HTML，前端直接崩。
 *
 * 判据：GET + Sec-Fetch-Dest 是 document/iframe/frame；没有该头时
 * 退化为看 Accept 是否含 text/html。
 */
function shouldRecoverWithToken(req) {
  if (req.method !== 'GET') return false
  const dest = req.headers['sec-fetch-dest']
  if (dest !== undefined) return dest === 'document' || dest === 'iframe' || dest === 'frame'
  const accept = req.headers.accept
  return typeof accept === 'string' && accept.includes('text/html')
}

/**
 * DeepSeek 账号登录的「回环改写」。
 *
 * ── 为什么必须这么做 ──────────────────────────────────────────────────────
 * DSH 的 DeepSeek 账号登录用回环地址的回调式 OAuth，后端的 loginOrigin()
 * 只接受 `http://127.0.0.1:<port>`、`http://localhost:<port>` 这类回环 origin，
 * 源码注释写得很明确：
 *     remote domains and path-based proxies are unsupported
 *
 * 而用户在飞牛桌面上访问的是 `http://<NAS-IP>:3080`（局域网地址），
 * 前端把 window.location.origin 原样传给后端，于是被 loginOrigin() 拒绝，
 * 界面表现为「点击登录直接失败」——错误码 account: protocol。
 *
 * ── 怎么绕过去 ────────────────────────────────────────────────────────────
 * 网关本来就把 Host 改写成 127.0.0.1:DSH_PORT 再转发。这里同样把登录的
 * callbackOrigin 改写成 `http://127.0.0.1:<DSH_PORT>`，于是：
 *   1. loginOrigin() 校验通过，登录流程能正常发起；
 *   2. 授权回调指向 127.0.0.1:<DSH_PORT>/oauth/callback —— 这个地址就在
 *      NAS 本机，DSH 自己的回调服务器能收到；
 *   3. 用户的浏览器通过网关访问同一个 DSH，回调请求也会被网关转发进去。
 *
 * 唯一的额外要求：用户浏览器必须能把授权完成的结果送回到 NAS 的
 * 127.0.0.1 —— 这一步由下面的 /login-relay 中转完成（见 handleLoginRelay）。
 */
const LOGIN_RPC_PATH = '/account/startSignIn'

/** 这个请求是不是「发起账号登录」的 RPC。 */
function isStartSignInRequest(targetPath) {
  return targetPath.split('?')[0] === `/api${LOGIN_RPC_PATH}`
}

/**
 * 把请求体里的 callbackOrigin 改写成回环地址。
 * 返回改写后的 JSON 字符串；不是可改写的结构就返回 undefined（原样转发）。
 */
function rewriteSignInOrigin(rawBody) {
  let body
  try {
    const text = rawBody.toString('utf8')
    body = JSON.parse(text)
  } catch {
    return undefined
  }
  const args = body?.payload?.args
  if (args === undefined || typeof args !== 'object') return undefined
  const original = args.callbackOrigin
  if (typeof original !== 'string') return undefined

  const loopback = `http://127.0.0.1:${DSH_PORT}`
  if (original === loopback) return undefined
  args.callbackOrigin = loopback
  log('INFO', `account login: callbackOrigin ${original} -> ${loopback} (loopback requirement)`)
  return Buffer.from(JSON.stringify(body), 'utf8')
}

/**
 * 登录回调中转。
 *
 * ── 还差哪一步 ────────────────────────────────────────────────────────────
 * 把 callbackOrigin 改写成回环地址后，登录能发起了，但 DeepSeek 授权完成后
 * 会把浏览器重定向到 `http://127.0.0.1:<DSH_PORT>/oauth/callback?code=...&state=...`。
 * 这串地址在**用户自己的电脑**上指着用户电脑，不是 NAS —— 直接打不开。
 *
 * ── 怎么补上 ──────────────────────────────────────────────────────────────
 * DSH 的回调处理器只校验 code + state，不看请求从哪来。所以网关在 NAS 上
 * 开放一个等价地址 `/dsh-cb`，收到 code/state 后原样转给内部 DSH 的
 * `/oauth/callback`，登录就此完成。
 *
 * 用户侧看到的操作是：点「登录」→ 弹出的授权页里点同意 → 页面主动把
 * code 送到 NAS 的 /dsh-cb。最后一步按下述方式自动完成：
 *   - 授权页跳转到 127.0.0.1 失败时，用户把地址栏那一串整个复制到本页
 *     提供的输入框即可（兜底）；
 *   - 更常见的路径是：我们在发起登录后把「回调中转地址」显示在界面上，
 *     用户授权后如果被跳到 127.0.0.1 打不开，把 URL 里的 code 粘贴回来。
 */
const CALLBACK_RELAY_PATH = '/dsh-cb'

/** 把 code/state 转给内部 DSH 的 /oauth/callback，返回 DSH 的状态码。 */
function relayLoginCallback(search) {
  return new Promise((resolve) => {
    const proxyReq = http.request(
      {
        host: DSH_HOST,
        port: DSH_PORT,
        method: 'GET',
        path: `/oauth/callback${search}`,
        headers: { host: `${DSH_HOST}:${DSH_PORT}` },
      },
      (proxyRes) => {
        let body = ''
        proxyRes.setEncoding('utf8')
        proxyRes.on('data', (c) => {
          if (body.length < 4096) body += c
        })
        proxyRes.on('end', () => resolve({ status: proxyRes.statusCode ?? 502, body }))
      },
    )
    proxyReq.on('error', (error) => resolve({ status: 502, body: error.message }))
    proxyReq.end()
  })
}

/** 用户看到的中转结果页。 */
function renderRelayResult(res, ok, detail) {
  const title = ok ? '登录已完成' : '登录未完成'
  const hint = ok
    ? '可以关闭这个页面，回到飞牛桌面继续使用 DeepSeek Harness。'
    : '请回到应用里重新点击登录。'
  const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title><style>
body{font-family:system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;
display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#fafafa;color:#1f2328}
.box{max-width:520px;padding:32px;background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08);text-align:center}
h1{font-size:20px;margin:0 0 12px}
p{line-height:1.7;margin:8px 0;font-size:14px;color:#57606a}
code{background:#f2f3f5;padding:2px 6px;border-radius:4px;font-size:12px}
</style></head><body><div class="box">
<h1>${ok ? '✅ ' : '⚠️ '}${title}</h1>
<p>${hint}</p>
${detail ? `<p><code>${detail}</code></p>` : ''}
</div></body></html>`
  res.writeHead(ok ? 200 : 400, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
  })
  res.end(html)
}

async function handleLoginRelay(req, res, search) {
  const url = new URL(`http://x${search}`)
  const code = url.searchParams.get('code')
  const state = url.searchParams.get('state')
  if (code === null || state === null) {
    renderRelayResult(res, false, '地址里缺少 code 或 state')
    return
  }
  const result = await relayLoginCallback(search)
  log('INFO', `login relay -> dsh status=${result.status}`)
  if (result.status >= 200 && result.status < 400) {
    renderRelayResult(res, true, '')
    return
  }
  // DSH 返回 400 通常是 state 不匹配（链接过期或重复使用）或登录已经完成。
  const reason =
    result.status === 400
      ? '登录链接已过期或已使用过，请回到应用重新点击登录'
      : result.status === 410
        ? '这次登录已经处理过了，请回到应用查看登录状态'
        : `登录服务返回 ${result.status}`
  renderRelayResult(res, false, reason)
}

/**
 * 登录回调粘贴页。
 *
 * ── 为什么需要这一页 ──────────────────────────────────────────────────────
 * DSH 把 OAuth 的 redirect_uri 写死成 `http://127.0.0.1:<内部端口>/oauth/callback`
 * （源码只有一处定义，无法通过配置改）。用户在浏览器里完成 DeepSeek 授权后，
 * DeepSeek 会把浏览器跳到这个地址 —— 而 127.0.0.1 指的是**用户自己的电脑**，
 * 不是 NAS，所以必然显示「拒绝连接」。
 *
 * 这不是我们的 bug，是上游把登录设计成「只有本机浏览器能用」的后果。
 *
 * ── 用户怎么完成登录 ──────────────────────────────────────────────────────
 * 打不开的那个页面，地址栏里其实已经带着 `?code=...&state=...`。
 * 让用户把整串地址复制粘贴到这里，网关解析出 code 转给 DSH，登录即成。
 *
 * 页面同时提供：
 *   - 一个输入框，接受「完整 URL」「只带查询串」或「纯 code」三种粘贴形式；
 *   - 实时解析预览，粘贴后立刻显示识别到了什么，不用盲猜；
 *   - 明确的图文步骤说明，普通用户照着做即可。
 */
function renderPastePage(res, prefill) {
  const safePrefill = String(prefill ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
  const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>完成 DeepSeek 账号登录</title><style>
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;
margin:0;padding:24px;background:#f5f6f8;color:#1f2328;line-height:1.6}
.wrap{max-width:640px;margin:0 auto}
.card{background:#fff;border-radius:14px;padding:28px 30px;box-shadow:0 2px 16px rgba(0,0,0,.07)}
h1{font-size:21px;margin:0 0 6px}
.sub{color:#6b7280;font-size:14px;margin:0 0 22px}
.steps{margin:0 0 24px;padding:0;list-style:none;counter-reset:s}
.steps li{position:relative;padding-left:38px;margin-bottom:16px;font-size:14.5px}
.steps li:before{counter-increment:s;content:counter(s);position:absolute;left:0;top:-1px;
width:24px;height:24px;border-radius:50%;background:#eef2ff;color:#4f46e5;
font-size:13px;font-weight:600;display:flex;align-items:center;justify-content:center}
.steps code{background:#f3f4f6;padding:1px 5px;border-radius:4px;font-size:13px}
.warn{background:#fffbeb;border-left:3px solid #f59e0b;padding:12px 14px;
border-radius:6px;font-size:13.5px;color:#92400e;margin-bottom:22px}
textarea{width:100%;min-height:92px;padding:12px 14px;border:1px solid #d1d5db;
border-radius:9px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
font-size:13px;line-height:1.55;resize:vertical}
textarea:focus{outline:none;border-color:#6366f1;box-shadow:0 0 0 3px rgba(99,102,241,.13)}
.feedback{margin-top:10px;font-size:13px;min-height:20px}
.ok{color:#059669}.bad{color:#dc2626}.muted{color:#6b7280}
button{margin-top:18px;width:100%;padding:12px;border:0;border-radius:9px;
background:#4f46e5;color:#fff;font-size:15px;font-weight:500;cursor:pointer}
button:disabled{background:#c7cbd6;cursor:not-allowed}
button:not(:disabled):hover{background:#4338ca}
.foot{margin-top:18px;font-size:12.5px;color:#9ca3af;text-align:center}
</style></head><body><div class="wrap"><div class="card">
<h1>完成 DeepSeek 账号登录</h1>
<p class="sub">最后一步：把登录后那个打不开的页面地址粘贴到这里。</p>

<div class="warn">
为什么会有这一步：DeepSeek 官方登录完成后会跳转到
<code>127.0.0.1</code>（本机地址）。你的浏览器在这台电脑上，
而应用跑在 NAS 上，所以那个页面你打不开 —— 但地址栏里的信息是有效的，
粘贴过来就能完成登录。
</div>

<ol class="steps">
<li>在刚才弹出的 DeepSeek 授权页里，点<strong>同意 / 授权</strong>。</li>
<li>页面会变成「无法访问此网站 / 拒绝连接」，这是正常的，<strong>不要关掉它</strong>。</li>
<li>点一下那个页面的<strong>地址栏</strong>，全选（Ctrl+A / ⌘+A）并复制（Ctrl+C / ⌘+C）。</li>
<li>把复制的内容粘贴到下面，点「完成登录」。</li>
</ol>

<textarea id="inp" placeholder="粘贴类似这样的地址：&#10;http://127.0.0.1:13900/oauth/callback?code=xxxx&amp;state=yyyy"></textarea>
<div class="feedback" id="fb"></div>
<button id="go" disabled>完成登录</button>
<div class="foot">也可以只粘贴 code 部分</div>
</div></div>
<script>
var inp=document.getElementById('inp'),fb=document.getElementById('fb'),go=document.getElementById('go');
var parsed=null;
function parse(v){
  v=(v||'').trim();
  if(!v) return null;
  // 1) 完整 URL 或带 ? 的查询串
  var q=v.indexOf('?')>=0?v.slice(v.indexOf('?')+1):(v.charAt(0)==='&'?v.slice(1):v);
  if(/[?&=]/.test(v)||v.indexOf('code=')>=0){
    try{var p=new URLSearchParams(q);var c=p.get('code'),s=p.get('state');
      if(c&&s) return {code:c,state:s};}catch(e){}
  }
  // 2) 只有 code —— 此时 state 缺失，必须提示。DSH 校验 state，纯 code 不够。
  return null;
}
function upd(){
  parsed=parse(inp.value);
  if(!inp.value.trim()){fb.textContent='';fb.className='feedback';go.disabled=true;return;}
  if(parsed){fb.textContent='✓ 已识别，可以点下面的按钮完成登录';fb.className='feedback ok';go.disabled=false;}
  else{fb.textContent='✗ 没识别出 code 和 state，请确认复制的是完整地址（要包含 code= 和 state=）';fb.className='feedback bad';go.disabled=true;}
}
inp.addEventListener('input',upd);
go.addEventListener('click',function(){
  if(!parsed) return;
  go.disabled=true;go.textContent='正在完成登录…';
  location.href='/dsh-cb?code='+encodeURIComponent(parsed.code)+'&state='+encodeURIComponent(parsed.state);
});
var pre=${JSON.stringify(safePrefill)};
if(pre){inp.value=pre;upd();}
</script></body></html>`
  res.writeHead(200, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
  })
  res.end(html)
}

// ─────────────────────────────────────────────── 访问门禁的页面
//
// 两个页面都必须能独立打开（不依赖 DSH 前端），因为它们出现在
// 「还没通过门禁」的时刻，此时前端资源本身也是拿不到的。

/** 令牌入口路径：桌面窗口里显示的「局域网访问安全连接」就指向这里。 */
const ACCESS_TOKEN_ENTRY_PATH = '/__access'

/** 桌面里查看/复制令牌的面板路径。 */
const ACCESS_PANEL_PATH = '/__access-panel'

/**
 * 「局域网访问安全连接」面板。
 *
 * 用户要求：令牌要在桌面窗口里看得见、能直接复制到浏览器打开。
 * 所以这里把完整链接渲染出来，并提供一个复制按钮。
 *
 * 注意：这个页面只有通过门禁后才能看到（桌面来源或已持 cookie），
 * 不会把令牌泄露给陌生人。
 */
function renderAccessPanel(req, res) {
  loadOrCreateAccessToken()
  const host = req.headers.host ?? `127.0.0.1:${LISTEN_PORT}`
  // 用请求的 Host 拼链接：用户从哪个地址访问，就给哪儿的链接，保证能打开。
  const link = `http://${host}${ACCESS_TOKEN_ENTRY_PATH}?access_token=${accessToken ?? ''}`
  const expires = accessTokenExpiresAt !== undefined ? new Date(accessTokenExpiresAt) : undefined
  const expiresText = expires !== undefined ? expires.toLocaleString('zh-CN') : '未知'
  const daysLeft =
    accessTokenExpiresAt !== undefined
      ? Math.max(0, Math.ceil((accessTokenExpiresAt - Date.now()) / 86400000))
      : 0

  const inner = `<h1>🔗 局域网访问安全连接</h1>
<p>把这个链接复制到任意浏览器（电脑、手机、平板都可以），就能直接打开 DeepSeek Harness，
不用先进入飞牛桌面。</p>
<div class="ok">
<p style="margin:0 0 8px"><strong>当前有效链接</strong>（剩余 ${daysLeft} 天）</p>
<p style="margin:0"><code id="link">${link}</code></p>
</div>
<p style="margin-top:18px">
<button id="cp" style="padding:10px 20px;border:0;border-radius:8px;background:#4f46e5;
color:#fff;font-size:15px;cursor:pointer">复制链接</button>
<span id="msg" style="margin-left:12px;color:#059669"></span>
</p>
<div class="warn">
<strong>请注意：</strong>这个链接等同于登录凭证，谁能打开它谁就能使用你的 DeepSeek Harness。
只发给你信任的人和自己的设备。不要发到公开群聊或截图里。<br>
有效期到 <strong>${expiresText}</strong>，到期后回到这个页面复制新链接即可。
</div>
<p style="font-size:13px;color:#9ca3af">
如果你只想在自己的设备上用，建议直接用飞牛桌面打开，不必复制链接。
</p>
<script>
var b=document.getElementById('cp'),m=document.getElementById('msg'),
    t=document.getElementById('link').textContent;
b.addEventListener('click',function(){
  var done=function(){m.textContent='已复制';setTimeout(function(){m.textContent=''},2000)};
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(t).then(done,function(){fallback()});
  }else{fallback()}
  function fallback(){
    var ta=document.createElement('textarea');ta.value=t;ta.style.position='fixed';
    ta.style.opacity='0';document.body.appendChild(ta);ta.select();
    try{document.execCommand('copy');done()}catch(e){m.textContent='请手动选中复制'}
    document.body.removeChild(ta);
  }
});
</script>`

  const { status, html } = pageShell('局域网访问安全连接', inner, 200)
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
  res.end(html)
}

function pageShell(title, inner, status) {
  return {
    status: status ?? 200,
    html: `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title><style>
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;
margin:0;padding:24px;background:#f5f6f8;color:#1f2328;line-height:1.65}
.wrap{max-width:600px;margin:0 auto}
.card{background:#fff;border-radius:14px;padding:30px;box-shadow:0 2px 16px rgba(0,0,0,.07)}
h1{font-size:20px;margin:0 0 14px}
p{font-size:14.5px;color:#4b5563;margin:10px 0}
code{background:#f3f4f6;padding:2px 6px;border-radius:4px;font-size:13px;word-break:break-all}
.warn{background:#fffbeb;border-left:3px solid #f59e0b;padding:12px 14px;
border-radius:6px;font-size:13.5px;color:#92400e;margin:16px 0}
.ok{background:#ecfdf5;border-left:3px solid #10b981;padding:12px 14px;
border-radius:6px;font-size:13.5px;color:#065f46;margin:16px 0}
</style></head><body><div class="wrap"><div class="card">${inner}</div></div></body></html>`,
  }
}

/**
 * 未授权访问的提示页。
 *
 * 这里不直接把令牌打印出来 —— 能把请求打到 3080 的人，未必有资格看令牌。
 * 提示用户去飞牛桌面里复制即可。
 */
function renderAccessDenied(req, res, url) {
  const wantsHtml =
    (req.headers['sec-fetch-dest'] === undefined &&
      typeof req.headers.accept === 'string' &&
      req.headers.accept.includes('text/html')) ||
    req.headers['sec-fetch-dest'] === 'document' ||
    req.headers['sec-fetch-dest'] === 'iframe'

  if (!wantsHtml) {
    res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' })
    res.end('DeepSeek Harness: 需要从飞牛桌面打开，或使用局域网访问令牌。\n')
    return
  }

  const { status, html } = pageShell(
    '需要授权',
    `<h1>需要从飞牛桌面打开</h1>
<p>DeepSeek Harness 现在只允许两种方式访问：</p>
<p><strong>1. 从飞牛桌面打开</strong>（推荐）<br>
在飞牛桌面点击 DeepSeek Harness 图标即可。</p>
<p><strong>2. 使用局域网访问令牌</strong><br>
在应用的桌面窗口里找到「局域网访问安全连接」，复制其中的链接。</p>
<div class="warn">
如果你确实是从飞牛桌面打开的却看到本页，说明浏览器缓存了旧地址，
请回到飞牛桌面重新点击图标。
</div>`,
    403,
  )
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
  res.end(html)
}

/**
 * 令牌入口页：校验 ?access_token= 并放行。
 *
 * 用户在桌面窗口里复制到的就是带令牌的完整链接，打开后这里种 cookie 并
 * 跳转到干净地址 —— 之后地址栏里不会再挂着一长串令牌。
 */
function renderTokenEntry(res, url) {
  const provided = url.searchParams.get('access_token')
  loadOrCreateAccessToken()
  const valid =
    provided !== null &&
    accessToken !== undefined &&
    accessTokenExpiresAt !== undefined &&
    Date.now() < accessTokenExpiresAt &&
    tokensEqual(provided, accessToken)

  if (!valid) {
    const { status, html } = pageShell(
      '链接无效或已过期',
      `<h1>⚠️ 链接无效或已过期</h1>
<p>这个局域网访问链接已经失效（有效期 30 天）。</p>
<p>请回到飞牛桌面，重新打开 DeepSeek Harness，在窗口里复制新的链接。</p>`,
      401,
    )
    res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
    res.end(html)
    return
  }

  const maxAge = Math.max(0, Math.floor((accessTokenExpiresAt - Date.now()) / 1000))
  const expires = new Date(accessTokenExpiresAt).toUTCString()
  res.writeHead(302, {
    location: '/',
    'cache-control': 'no-store',
    'set-cookie': `dsh-access=${accessToken}; Max-Age=${maxAge}; Path=/; HttpOnly; SameSite=Lax; Expires=${expires}`,
  })
  res.end()
}

/**
 * 注入到 HTML 里的一小段脚本：把「绝对路径」请求补回网关前缀。
 *
 * ── 为什么必须这么做 ──────────────────────────────────────────────────────
 * 通过飞牛统一网关访问时，应用挂载在子路径 /app/DeepSeekHarness/ 下。
 * 但第三方前端插件（如 dsh-connect-workbuddy）会直接写：
 *     fetch("/plugins/dsh-connect-workbuddy/cli-live")
 * 绝对路径 → 浏览器请求 http://NAS:5666/plugins/... → **丢掉前缀** →
 * 飞牛 nginx 把它路由到别的应用（实测打到了 trim_photos 相册服务）→ 502。
 *
 * 实测日志：
 *   GET /plugins/dsh-connect-workbuddy/cli-live  主机 <NAS-IP>:5666
 *   上游 unix:/var/run/trim_photos.sock  → 502
 *
 * ── 为什么改前端而不是改插件 ──────────────────────────────────────────────
 * 插件来自插件市场，升级会覆盖，改它不持久。在网关注入拦截是所有插件通用的，
 * 升级 dsh 或插件都不影响。
 *
 * 只拦「以 / 开头且不是本应用前缀」的请求，其它（http、相对路径、
 * 已经带前缀的）一律不动，避免误伤。
 */
const PREFIX_PATCH_SCRIPT = `
<script data-dsh-gateway="1">
(function () {
  var PREFIX = ${JSON.stringify(PREFIX)};
  function fix(u) {
    if (typeof u !== "string") return u;
    if (!u || u.charAt(0) !== "/") return u;      // 相对路径 / http(s) 不动
    if (u.indexOf("//") === 0) return u;
    if (u === PREFIX || u.indexOf(PREFIX + "/") === 0) return u;
    return PREFIX + u;                             // 补前缀
  }
  var of = window.fetch;
  if (of) {
    window.fetch = function (input, init) {
      try {
        if (typeof input === "string") input = fix(input);
        else if (input && input.url) {
          var fixed = fix(input.url);
          if (fixed !== input.url) input = new Request(fixed, input);
        }
      } catch (e) {}
      return of.call(this, input, init);
    };
  }
  var oo = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (m, u) {
    var a = Array.prototype.slice.call(arguments);
    try { a[1] = fix(u); } catch (e) {}
    return oo.apply(this, a);
  };
})();
</script>
`

/** 在 </head> 前插入脚本；没有 head 就插到最前面。 */
/**
 * 服务端改写 HTML 里的「绝对路径」静态资源引用，补上网关前缀。
 *
 * ── 为什么必须在服务端改，不能靠前端脚本 ──────────────────────────────────
 * 第三方插件（如 dsh-whale-widget）会在服务端往 HTML 里注入：
 *     <script src="/dsh-whale/widget.js"></script>
 * 这是浏览器**原生加载**的，在我们注入的 JS 跑起来之前请求就已经发出去了，
 * 前端拦截 fetch/XHR 根本管不到。表现就是：
 *     页面从 /app/DeepSeekHarness/ 打开，却去请求 /dsh-whale/widget.js
 *     → 丢掉前缀 → 飞到飞牛网关根路径 → 404 → 挂件不显示。
 * 实测 nginx 日志：GET /dsh-whale/widget.js → 404（referrer 是本应用页面）。
 *
 * 所以必须在 HTML 文本层面改写 src/href。
 *
 * 只改「以 / 开头、且不是本应用前缀、不是 // 协议相对」的引用，
 * 其余（相对路径、http(s) 绝对地址、data:）一律不动，避免误伤。
 */
function rewriteAbsoluteAssetPaths(html) {
  const prefixed = PREFIX.replaceAll('/', '\\/')
  // 匹配 src="..." / href="..."，只处理以单个 / 开头且尚未带前缀的值
  return html.replace(
    /\b(src|href)=(["'])(\/(?!\/)[^"']*)\2/gi,
    (whole, attr, quote, value) => {
      if (value === PREFIX || value.startsWith(PREFIX + '/')) return whole
      return `${attr}=${quote}${PREFIX}${value}${quote}`
    },
  )
}

function injectPatchScript(html) {
  if (html.includes('data-dsh-gateway="1"')) return html
  // 先改写静态资源绝对路径（<script src>、<link href> 等）
  let out = rewriteAbsoluteAssetPaths(html)
  const i = out.search(/<\/head\s*>/i)
  if (i !== -1) return out.slice(0, i) + PREFIX_PATCH_SCRIPT + out.slice(i)
  const j = out.search(/<body[^>]*>/i)
  if (j !== -1) return out.slice(0, j) + PREFIX_PATCH_SCRIPT + out.slice(j)
  return PREFIX_PATCH_SCRIPT + out
}

/**
 * 这个响应是不是需要改写路径的 JS（插件前端脚本）。
 *
 * 为什么 JS 也要改：
 * 有些插件把资源路径硬编码在**前端 JS 里**，而不是 HTML 的 src 属性，例如
 * dsh-whale-widget 的 widget.js 内就有 48 处：
 *     url: '/dsh-whale/image.png'
 *     url: '/dsh-whale/bubble-img.png?id=...'
 * 这些是运行时由 JS 拼出来的请求，HTML 改写碰不到；前端 fetch 拦截也管不了
 * （图片是 <img src> / new Image 加载的）。子路径部署时必然 404 ——
 * 表现就是「Web 端正常、飞牛桌面端图片全部裂开」。
 *
 * 只处理插件目录下的脚本（/plugins/、/dsh-* 这类），不动 DSH 自己的
 * bundle：那些走的是相对路径，改了反而会坏。
 */
function isPluginScript(headers, targetPath) {
  const ct = headers['content-type']
  if (typeof ct !== 'string') return false
  const lower = ct.toLowerCase()
  const isJs =
    lower.includes('javascript') || lower.includes('ecmascript') || lower.includes('text/plain')
  if (!isJs) return false
  // 只改插件自己的脚本，避开 DSH 核心 bundle
  return /^\/(plugins|dsh-[a-z0-9-]+)\//.test(targetPath)
}

/** 改写 JS 里以 / 开头且未带前缀的资源路径字面量。 */
function rewritePluginScriptPaths(code) {
  const prefixed = PREFIX.replaceAll('/', '\\/')
  // 匹配 '...' 或 "..." 中完整以西单斜杠开头的路径（排除 // 协议相对）
  return code.replace(
    /([\"'])(\/(?!\/)(?!app\/)[^\"'\n]{1,200}?)\1/g,
    (whole, quote, value) => {
      if (value.startsWith(PREFIX + '/')) return whole
      return `${quote}${PREFIX}${value}${quote}`
    },
  )
}

/** 缓冲并改写插件 JS 响应。 */
function pipeScriptWithPatch(req, res, proxyRes, headers, targetPath) {
  const chunks = []
  let size = 0
  const LIMIT = 8 * 1024 * 1024
  proxyRes.on('data', (c) => {
    if (size > LIMIT) return
    size += c.length
    chunks.push(c)
  })
  proxyRes.on('end', () => {
    let body = Buffer.concat(chunks)
    const enc = String(headers['content-encoding'] ?? '').toLowerCase()
    let decoded = false
    try {
      if (enc === 'gzip') { body = zlib.gunzipSync(body); decoded = true }
      else if (enc === 'deflate') { body = zlib.inflateSync(body); decoded = true }
      else if (enc === 'br') { body = zlib.brotliDecompressSync(body); decoded = true }
    } catch (error) {
      log('WARN', `script rewrite skipped (decode ${enc}): ${error.message}`)
    }
    if (size > LIMIT) {
      const h = { ...headers, 'content-length': String(body.length) }
      delete h['content-encoding']
      res.writeHead(proxyRes.statusCode ?? 200, h)
      res.end(body)
      return
    }
    const out = decoded || enc === ''
      ? Buffer.from(rewritePluginScriptPaths(body.toString('utf8')), 'utf8')
      : body
    const h = { ...headers, 'content-length': String(out.length) }
    delete h['content-encoding']
    delete h['transfer-encoding']
    res.writeHead(proxyRes.statusCode ?? 200, h)
    res.end(out)
  })
  proxyRes.on('error', () => {
    if (!res.headersSent) res.writeHead(502).end()
    else res.end()
  })
}

/** 这个响应是不是需要注入的 HTML 文档。 */
function isHtmlDocument(headers) {
  const ct = headers['content-type']
  return typeof ct === 'string' && ct.toLowerCase().includes('text/html')
}

/** 缓冲并改写 HTML 响应（只用于文档请求，体积有限）。 */
function pipeHtmlWithPatch(req, res, proxyRes, headers) {
  const chunks = []
  let size = 0
  const LIMIT = 4 * 1024 * 1024
  proxyRes.on('data', (c) => {
    if (size > LIMIT) return
    size += c.length
    chunks.push(c)
  })
  proxyRes.on('end', () => {
    if (size > LIMIT) {
      // 超过上限就放弃注入，原样返回（避免拖垮大文档）
      const buf = Buffer.concat(chunks)
      const h = { ...headers, 'content-length': String(buf.length) }
      delete h['content-encoding']
      res.writeHead(proxyRes.statusCode ?? 200, h)
      res.end(buf)
      return
    }
    let body = Buffer.concat(chunks)
    // DSH 默认 gzip；注入前必须先解压，否则改的是压缩字节。
    const enc = String(headers['content-encoding'] ?? '').toLowerCase()
    try {
      if (enc === 'gzip') body = zlib.gunzipSync(body)
      else if (enc === 'deflate') body = zlib.inflateSync(body)
      else if (enc === 'br') body = zlib.brotliDecompressSync(body)
    } catch (error) {
      log('WARN', `inline script inject skipped (decode ${enc} failed): ${error.message}`)
      const h = { ...headers, 'content-length': String(body.length) }
      delete h['content-encoding']
      res.writeHead(proxyRes.statusCode ?? 200, h)
      res.end(body)
      return
    }
    let html = body.toString('utf8')
    html = injectPatchScript(html)
    const out = Buffer.from(html, 'utf8')
    const h = { ...headers, 'content-length': String(out.length) }
    delete h['content-encoding']
    delete h['transfer-encoding']
    res.writeHead(proxyRes.statusCode ?? 200, h)
    res.end(out)
  })
  proxyRes.on('error', () => {
    if (!res.headersSent) res.writeHead(502).end()
    else res.end()
  })
}

function handleRequest(req, res) {
  const originalUrl = req.url || '/'
  const requestUrl = new URL(originalUrl, 'http://gateway.invalid')

  // ── 访问门禁 ────────────────────────────────────────────────────────────
  //
  // 旧逻辑的漏洞：只有「带了身份头」时才检查管理员，于是端口直连（没头）
  // 直接放行。而这个网关无条件把 Host 改写成 127.0.0.1，DSH 的 Host/Origin
  // 栅栏因此永久放行，最后一层只剩「有没有 cookie」——而 token 交换是自动的。
  // 实测结论：任何人 curl http://NAS:3080/ 都能拿到完整会话。
  //
  // 现在改为**默认拒绝**：必须满足其一才放行
  //   a) 来自飞牛桌面（带任意 X-Trim-* 头）
  //   b) 持有有效的 30 天局域网访问令牌（?access_token= 或 dsh-access cookie）
  //
  // 令牌入口必须豁免门禁本身，否则用户没法用令牌进来。
  // ── 谁算「来自飞牛桌面」 ────────────────────────────────────────────────
  //
  // 之前我用「请求是否来自 unix socket」判断，这是**错的**，实测把桌面自己
  // 挡在外面（用户看到「需要从飞牛桌面打开」，刷新/重装都无效）。
  //
  // 官方文档说得很清楚（app-entry「访问模型」）：
  //   「端口服务：入口打开应用自己的服务端口。这种方式和 NAS 用户登录态无关」
  //   「统一网关：转发到服务前校验，并提供用户 Header」
  //
  // 也就是说：走端口的桌面访问根本不会带 X-Trim-* 头；只有走**统一网关**
  // （gatewaySocket + gatewayPrefix）时才由飞牛注入 X-Trim-Userid /
  // X-Trim-Isadmin / X-Trim-Username。
  //
  // 所以判据改为「有没有可信身份头」：
  //   - 统一网关转发 → 带 X-Trim-*（飞牛注入，客户端伪造不了，因为
  //     网关会覆盖同名头）→ 桌面，放行；
  //   - 局域网直连端口 → 没有这些头 → 必须持令牌才能进。
  const fromGateway = isGatewayForwarded(req)
  const hasIdentity = fromGateway
  const tokenOk = hasValidAccessToken(req, requestUrl)
  // 经网关访问时路径带 /app/DeepSeekHarness 前缀，直连端口时没有。
  // 两种形态都要认，否则桌面里打开令牌面板会 404/302。
  const intraPath = stripPrefix(requestUrl.pathname + requestUrl.search).split('?')[0]
  const isTokenEntry =
    requestUrl.pathname === ACCESS_TOKEN_ENTRY_PATH || intraPath === ACCESS_TOKEN_ENTRY_PATH
  const isPanel = requestUrl.pathname === ACCESS_PANEL_PATH || intraPath === ACCESS_PANEL_PATH

  if (ENFORCE_ADMIN && !fromGateway && !tokenOk && !isTokenEntry) {
    log('WARN', `拒绝未授权访问: ${requestUrl.pathname} from ${req.socket?.remoteAddress ?? '?'}`)
    renderAccessDenied(req, res, requestUrl)
    return
  }

  // 统一网关会给出 X-Trim-Isadmin；明确为 false 时拒绝（仅管理员可用）。
  if (ENFORCE_ADMIN && fromGateway && req.headers['x-trim-isadmin'] === 'false') {
    res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' })
    res.end('DeepSeek Harness 仅限管理员访问。请使用管理员账号登录飞牛 fnOS。\n')
    return
  }

  // 用令牌进来的，落地后种 cookie，后续请求不必再带查询参数。
  if (tokenOk && !hasIdentity) {
    const fromQuery = requestUrl.searchParams.get('access_token')
    if (fromQuery !== null) {
      const maxAge = Math.max(0, Math.floor(((accessTokenExpiresAt ?? 0) - Date.now()) / 1000))
      res.setHeader(
        'set-cookie',
        `dsh-access=${accessToken}; Max-Age=${maxAge}; Path=/; HttpOnly; SameSite=Lax`,
      )
    }
  }

  // 令牌入口：校验并放行（必须在其它路由之前处理）。
  if (isTokenEntry) {
    renderTokenEntry(res, requestUrl)
    return
  }

  // 桌面窗口里的「局域网访问安全连接」面板。
  // 只有通过门禁的请求才会走到这里，所以能把令牌展示出来。
  if (isPanel) {
    renderAccessPanel(req, res)
    return
  }

  const targetPath = stripPrefix(originalUrl)

  // ── 登录回调中转 ────────────────────────────────────────────────────────
  // 必须放在 token 检查之前：用户可能还没拿到 cookie 就先打开回调链接，
  // 这时把请求 302 到带 token 的地址会把 code/state 丢掉。
  {
    const q = targetPath.indexOf('?')
    const cbPath = q === -1 ? targetPath : targetPath.slice(0, q)
    if (cbPath === CALLBACK_RELAY_PATH) {
      // 没有 code/state 时不是错误 —— 这正是用户手动打开粘贴页的入口。
      // 用户授权后被跳到打不开的 127.0.0.1，回头点「完成登录」就落到这里。
      const hasCode = /[?&]code=/.test(targetPath)
      if (!hasCode) {
        renderPastePage(res, '')
        return
      }
      handleLoginRelay(req, res, q === -1 ? '' : targetPath.slice(q))
      return
    }
  }

  // 首次访问：没有 DSH cookie 也没有 token 时，302 到带 token 的地址。
  //
  // 用户永远看不到这一步：302 → DSH 校验 token → 303 + Set-Cookie → 回到
  // 干净地址。整个过程在浏览器内自动完成，这就是「桌面点开即登录」。
  // token 只在跳转 URL 里出现一次，落地页是干净的 `./`。
  if (!hasDshCookie(req) && !/[?&]token=/.test(targetPath)) {
    res.writeHead(302, {
      location: loginRedirectPath(originalUrl),
      'cache-control': 'no-store',
      'referrer-policy': 'no-referrer',
    })
    res.end()
    return
  }

  // ── 账号登录：需要读改写请求体 ──────────────────────────────────────────
  // 只对 startSignIn 这一个端点做缓冲与改写，其余请求保持流式直通，
  // 避免影响上传、长连接和大响应。
  if (req.method === 'POST' && isStartSignInRequest(targetPath)) {
    const chunks = []
    let size = 0
    const LIMIT = 1024 * 1024
    req.on('data', (chunk) => {
      size += chunk.length
      if (size <= LIMIT) chunks.push(chunk)
    })
    req.on('end', () => {
      const raw = Buffer.concat(chunks)
      const rewritten = rewriteSignInOrigin(raw)
      const headers = forwardHeaders(req)
      if (rewritten !== undefined) {
        headers['content-length'] = String(rewritten.length)
        delete headers['transfer-encoding']
      }
      const proxyReq = http.request(
        {
          host: DSH_HOST,
          port: DSH_PORT,
          method: 'POST',
          path: targetPath,
          headers,
        },
        (proxyRes) => {
          res.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers)
          proxyRes.pipe(res)
        },
      )
      proxyReq.on('error', (error) => {
        log('ERROR', `signin proxy failed: ${error.message}`)
        if (!res.headersSent) {
          res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' })
          res.end('DeepSeek Harness 服务未就绪，请稍后重试。\n')
        } else {
          res.end()
        }
      })
      proxyReq.end(rewritten !== undefined ? rewritten : raw)
    })
    req.on('error', () => {
      if (!res.headersSent) res.writeHead(400).end()
    })
    return
  }

  const proxyReq = http.request(
    { host: DSH_HOST, port: DSH_PORT, method: req.method, path: targetPath, headers: forwardHeaders(req) },
    (proxyRes) => {
      const status = proxyRes.statusCode ?? 502

      // DSH 判定 cookie 无效（旧 authority、过期、换端口之后）。对文档请求
      // 重走 token 流程，让浏览器拿到一份新 cookie；其余请求原样透传。
      if (status === 401 && launchToken !== undefined && shouldRecoverWithToken(req)) {
        proxyRes.resume()
        log('INFO', `401 from dsh on ${targetPath}, redirecting to token flow`)
        res.writeHead(302, {
          location: loginRedirectPath(originalUrl),
          'cache-control': 'no-store',
          'referrer-policy': 'no-referrer',
        })
        res.end()
        return
      }

      // HTML 文档：注入「补前缀」脚本，让写死绝对路径的前端插件也能工作。
      // 其它响应（JS/CSS/JSON/流）保持流式直通，不改写、不缓冲。
      if (status === 200 && req.method === 'GET' && isHtmlDocument(proxyRes.headers)) {
        pipeHtmlWithPatch(req, res, proxyRes, proxyRes.headers)
        return
      }
      // 插件前端脚本：改写里面硬编码的资源路径（图片等）。
      if (status === 200 && req.method === 'GET' && isPluginScript(proxyRes.headers, targetPath)) {
        pipeScriptWithPatch(req, res, proxyRes, proxyRes.headers, targetPath)
        return
      }
      res.writeHead(status, proxyRes.headers)
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
  const upgradeUrl = new URL(originalUrl, 'http://gateway.invalid')

  // WebSocket 必须走和 HTTP 一样的门禁，否则 RPC 通道会绕过检查：
  // 工具调用、会话操作全部走 /api/remote.mux 的 WebSocket，
  // 只堵 HTTP 而不堵这里，等于门只关了一半。
  const fromGateway = isGatewayForwarded(req)
  const hasIdentity = fromGateway
  const tokenOk = hasValidAccessToken(req, upgradeUrl)
  if (ENFORCE_ADMIN && !fromGateway && !tokenOk) {
    log('WARN', `拒绝未授权的 WebSocket: ${upgradeUrl.pathname}`)
    socket.end('HTTP/1.1 403 Forbidden\r\n\r\n')
    return
  }

  if (ENFORCE_ADMIN && fromGateway && req.headers['x-trim-isadmin'] === 'false') {
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
function createServer(label, channel) {
  // 把「请求来自哪条监听通道」挂到 req 上。
  //
  // 这是判断「是不是飞牛桌面」唯一可靠的依据：
  //   - unix socket 由飞牛网关进程内部转发，外部网络无法直连它，
  //     所以走 socket 的请求一定来自飞牛桌面/统一网关；
  //   - TCP 端口是全网卡监听的，任何人都能连，也因此任何人都能伪造
  //     X-Trim-* 请求头 —— 只靠头判断等于没判断（已实测可过）。
  const server = http.createServer((req, res) => {
    req.__dshChannel = channel
    handleRequest(req, res)
  })
  server.on('upgrade', (req, socket, head) => {
    req.__dshChannel = channel
    handleUpgrade(req, socket, head)
  })
  server.on('clientError', (_error, socket) => socket.destroy())
  server.on('error', (error) => {
    // 单条通道失败不能拖垮另一条：socket 建不起来时 TCP 往往仍然可用，
    // 反之亦然。全部失败才算致命（在 startServers 里判断）。
    log('ERROR', `${label} 监听失败: ${error.message}`)
    // 端口占用是最常见的启动失败，单独给一句用户能看懂的说明：
    // 只说 "EADDRINUSE" 用户不知道该怎么办。
    if (error.code === 'EADDRINUSE') {
      const port = label === 'tcp' ? LISTEN_PORT : label
      failLoud(
        `端口 ${port} 已被其他程序占用。请在「应用中心 → DeepSeek Harness → 设置」里换一个端口，` +
          `或先停掉占用该端口的程序。`,
      )
    }
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
    const socketServer = createServer('unix socket', 'socket')
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
    const tcpServer = createServer('tcp', 'tcp')
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
