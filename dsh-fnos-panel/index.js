/**
 * dsh-fnos-panel —— 飞牛 fnOS 的「跨设备访问 / 账号登录」面板（Host 侧）
 * ============================================================================
 *
 * 这个插件解决的问题
 * ------------------
 * 1. 用户想在手机、平板、另一台电脑上直接用 DeepSeek Harness，但不想每次
 *    都先登飞牛桌面。需要一个带令牌的直连链接。
 * 2. DeepSeek 账号登录在 NAS 上很别扭：官方把 redirect_uri 写死成
 *    127.0.0.1，用户授权后浏览器会跳到他自己电脑的本机地址，必然打不开。
 *    需要一个「把地址栏粘回来」的入口。
 *
 * 为什么这些必须在 Host 侧做
 * --------------------------
 * - 访问令牌存在 @appdata/access-token.env，只有服务端读得到；
 * - **服务端口只有服务端知道**：用户在浏览器里看到的地址是飞牛网关的
 *   5666，不是应用自己的 3080。纯前端拼链接必然拼错（这是之前真实踩过的坑）。
 *   这里从 TRIM_SERVICE_PORT / DSH_SERVICE_PORT 读，用户改端口后自动跟上。
 *
 * 职责划分
 * --------
 * 本文件（Host）：读令牌、读端口、代发登录回调、报告登录状态。
 * 前端（client.js）：渲染侧栏入口与弹窗，IP 用 window.location.hostname。
 */

const ACCESS_TOKEN_ENV = 'access-token.env'
const ENTRY_PATH = '/__access'

export const name = 'dsh-fnos-panel'

/** 前端需要注入的 DSH 客户端包（缺了会加载失败）。 */
export const inject = ['webServer', 'credentials']

/**
 * 读访问令牌文件。
 * 与网关共用同一份 @appdata/access-token.env，两边永远一致。
 */
async function readAccessToken(ctx, fsPromises, pathMod) {
  const varDir =
    process.env.TRIM_PKGVAR || process.env.DSH_PKGVAR || process.env.DSH_VAR || ''
  if (varDir === '') return undefined
  try {
    const raw = await fsPromises.readFile(pathMod.join(varDir, ACCESS_TOKEN_ENV), 'utf8')
    const parsed = JSON.parse(raw)
    if (
      typeof parsed?.token === 'string' &&
      typeof parsed?.expiresAt === 'number' &&
      parsed.expiresAt > Date.now()
    ) {
      return { token: parsed.token, expiresAt: parsed.expiresAt }
    }
  } catch {
    // 文件不存在/格式不对都当作「暂无令牌」，前端会提示重新安装或重启
  }
  return undefined
}

/** 服务端口：优先环境变量，用户改端口后这里会自动变。 */
function readServicePort() {
  const candidates = [
    process.env.DSH_SERVICE_PORT,
    process.env.TRIM_SERVICE_PORT,
  ]
  for (const c of candidates) {
    const n = Number(String(c ?? '').trim())
    if (Number.isFinite(n) && n > 0 && n <= 65535) return n
  }
  return 3080
}

/** 拼一个 JSON 响应。 */
function json(res, status, body) {
  const text = JSON.stringify(body)
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': String(Buffer.byteLength(text)),
  })
  res.end(text)
}

/**
 * 把用户粘贴的回调地址里的 code/state 转给 DSH 自己的 /oauth/callback。
 *
 * 为什么要中转：DSH 的回调处理在内部端口上，只认 code+state，不看来源。
 * 面板拿到用户粘贴的地址后，由 Host 代发一次请求，登录即在服务端完成。
 */
async function relayCallback(ctx, code, state) {
  const httpMod = await import('node:http')
  const port = Number(process.env.DSH_INTERNAL_PORT || 0)
  if (!Number.isFinite(port) || port <= 0) {
    return { ok: false, reason: '无法确定内部端口，请重启应用后重试' }
  }
  const qs = `?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`
  return await new Promise((resolve) => {
    const req = httpMod.request(
      {
        host: '127.0.0.1',
        port,
        method: 'GET',
        path: `/oauth/callback${qs}`,
        headers: { host: `127.0.0.1:${port}` },
        timeout: 15000,
      },
      (r) => {
        r.resume()
        r.on('end', () => {
          if (r.statusCode && r.statusCode >= 200 && r.statusCode < 400) resolve({ ok: true })
          else if (r.statusCode === 400)
            resolve({ ok: false, reason: '登录链接已过期或已被使用，请重新点登录' })
          else if (r.statusCode === 410)
            resolve({ ok: false, reason: '这次登录已经被处理过了，请查看上方状态' })
          else resolve({ ok: false, reason: `登录服务返回 ${r.statusCode}` })
        })
      },
    )
    req.on('timeout', () => {
      req.destroy()
      resolve({ ok: false, reason: '等待登录服务超时，请重试' })
    })
    req.on('error', (e) => resolve({ ok: false, reason: `连接登录服务失败：${e.message}` }))
    req.end()
  })
}

/**
 * 读当前 DeepSeek 账号登录状态。
 *
 * 通过 credentials 服务读 DSH 自己维护的凭据记录：有 deepseek 账号的
 * grant 记录就算已登录。前端定时轮询这里，用户在设置里退出登录后，
 * 面板会在下一次轮询时回到「未登录」提示。
 */

export function apply(ctx) {
  ctx.effect(() => {
    const off = ctx.webServer.register({
      kind: 'exact',
      path: '/plugins/dsh-fnos-panel/access-info',
      handler: async (req, res) => {
        const fsPromises = await import('node:fs/promises')
        const pathMod = await import('node:path')
        const info = await readAccessToken(ctx, fsPromises, pathMod)
        if (info === undefined) {
          json(res, 200, { ok: false, reason: 'no-token' })
          return
        }
        json(res, 200, {
          ok: true,
          token: info.token,
          expiresAt: info.expiresAt,
          port: readServicePort(),
          entryPath: ENTRY_PATH,
        })
      },
    })
    return () => off?.()
  })

  // ── 开始登录 ────────────────────────────────────────────────────────────
  // 由插件自己发起登录尝试，而不是让用户去设置里点。
  //
  // 为什么必须这样：
  //   实测 DSH 的 /oauth/callback 路由**只在登录尝试进行中存在**
  //     · 未发起登录 → 请求回调得到 404（路由不存在）
  //     · 发起登录后 → 请求回调得到 400（路由存在，state 不匹配）
  //   而登录尝试存活时间只有 10~18 秒（DeepSeek 返回的 expires_in 很短）。
  //   如果让用户去设置里登录，等完成授权回来，尝试早已过期、路由早没了，
  //   粘贴就必然 404 —— 这正是之前踩到的坑。
  //
  //   所以：面板自己发起 → 立刻把授权链接给用户 → 用户就地授权 →
  //   回来后路由仍在，粘贴即可完成。
  ctx.effect(() => {
    const off = ctx.webServer.register({
      kind: 'exact',
      path: '/plugins/dsh-fnos-panel/start-login',
      handler: async (req, res) => {
        const account = ctx.get('deepseekAccount')
        if (account === undefined || typeof account.startSignIn !== 'function') {
          json(res, 200, { ok: false, reason: '账号登录服务未就绪，请稍后重试' })
          return
        }
        const internalPort = Number(process.env.DSH_INTERNAL_PORT || 0)
        if (!Number.isFinite(internalPort) || internalPort <= 0) {
          json(res, 200, { ok: false, reason: '无法确定内部端口，请重启应用后重试' })
          return
        }
        try {
          // 与官方前端一致的参数：client 元信息 + 回环 callbackOrigin + web 来源。
          // callbackOrigin 必须是回环地址，否则被 loginOrigin() 拒绝。
          const result = await account.startSignIn(
            {
              version: '0.2.2-rc.5',
              locale: 'zh-CN',
              timezoneOffsetSeconds: -new Date().getTimezoneOffset() * 60,
            },
            `http://127.0.0.1:${internalPort}`,
            'web',
          )
          // startSignIn 返回时 phase 还是 initializing，authorizeUrl 尚未生成
          // （它要等 DeepSeek 的 auth_init 返回）。所以这里轮询 getState()，
          // 最多等 15 秒拿到 authorizeUrl 再返回给前端。
          let attempt = result?.attempt ?? {}
          let authorizeUrl =
            typeof attempt.authorizeUrl === 'string' ? attempt.authorizeUrl : ''
          const deadline = Date.now() + 15000
          while (
            authorizeUrl === '' &&
            Date.now() < deadline &&
            typeof account.getState === 'function'
          ) {
            await new Promise((r) => setTimeout(r, 400))
            try {
              const st = await account.getState()
              attempt = st?.attempt ?? attempt
              if (typeof attempt.authorizeUrl === 'string') authorizeUrl = attempt.authorizeUrl
              // 已经失败/过期就别再等
              if (attempt.phase === 'failed' || attempt.phase === 'expired') break
            } catch {
              break
            }
          }
          if (authorizeUrl === '') {
            json(res, 200, {
              ok: false,
              reason: '没能拿到授权链接，请稍后重试',
              phase: attempt.phase,
            })
            return
          }
          json(res, 200, {
            ok: true,
            authorizeUrl,
            expiresAt: typeof attempt.expiresAt === 'number' ? attempt.expiresAt : undefined,
          })
        } catch (error) {
          json(res, 200, { ok: false, reason: `发起登录失败：${error?.message ?? error}` })
        }
      },
    })
    return () => off?.()
  })

  ctx.effect(() => {
    const off = ctx.webServer.register({
      kind: 'exact',
      path: '/plugins/dsh-fnos-panel/complete-login',
      handler: async (req, res) => {
        if (req.method !== 'POST') {
          json(res, 405, { ok: false, reason: 'method not allowed' })
          return
        }
        const chunks = []
        let size = 0
        req.on('data', (c) => {
          size += c.length
          if (size <= 64 * 1024) chunks.push(c)
        })
        req.on('end', async () => {
          let body
          try {
            body = JSON.parse(Buffer.concat(chunks).toString('utf8'))
          } catch {
            json(res, 400, { ok: false, reason: '请求格式不正确' })
            return
          }
          const code = typeof body?.code === 'string' ? body.code.trim() : ''
          const state = typeof body?.state === 'string' ? body.state.trim() : ''
          if (code === '' || state === '') {
            json(res, 400, { ok: false, reason: '没识别出 code 或 state，请粘贴完整地址' })
            return
          }
          json(res, 200, await relayCallback(ctx, code, state))
        })
      },
    })
    return () => off?.()
  })
}
