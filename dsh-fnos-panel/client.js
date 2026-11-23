window.__ModuleLoader__.load({
  id: 'dsh-fnos-panel',
  factory: function (require) {
    var React = require('react')
    var module = { exports: {} }

    /**
     * dsh-fnos-panel —— 前端部分（Client）
     * ==========================================================================
     *
     * 侧栏「注意事项」入口，点击弹出面板。两个板块横向并列、点击切换：
     *   [跨设备访问] [账号登录]
     *
     * 关键实现细节（都是踩过坑总结的）
     * ---------------------------------
     * 1. IP 从浏览器取，端口从 Host 取。
     *    用户在飞牛桌面看到的地址是 http://NAS:5666/app/DeepSeekHarness/，
     *    5666 是飞牛网关端口，不是应用端口。用 window.location.port 拼链接会
     *    飞到网关根路径，必然打不开。端口必须由服务端提供。
     *
     * 2. 登录必须由面板自己发起，不能引导用户去设置里点。
     *    实测 DSH 的 /oauth/callback 路由只在登录尝试期间存在，而尝试只存活
     *    10~18 秒。用户去设置里登录、授权完再回来，尝试早已过期、路由已销毁，
     *    粘贴必然 404。所以面板先调 /start-login 拿授权链接，用户就地授权，
     *    回来后路由仍在。
     *
     * 3. 登录状态每 5 秒轮询：用户在设置里自行退出登录时，面板要及时回到
     *    「未登录」提示。
     */

    const API_BASE = '/plugins/dsh-fnos-panel'
    const SLOT = 'sidebar.footer.action'

    // ── 样式 ────────────────────────────────────────────────────────────────
    const S = {
      overlay: {
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,.45)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 9999,
        padding: '24px',
      },
      dialog: {
        background: 'var(--dsw-alias-bg-base, #fff)',
        color: 'var(--dsw-alias-label-primary, #1f2328)',
        borderRadius: '14px',
        boxShadow: '0 12px 48px rgba(0,0,0,.22)',
        width: '100%',
        maxWidth: '660px',
        maxHeight: '86vh',
        overflowY: 'auto',
        padding: '22px 26px 24px',
        fontFamily: 'system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif',
        lineHeight: 1.65,
        fontSize: '14px',
      },
      tabs: {
        display: 'flex',
        gap: '6px',
        borderBottom: '1px solid #e5e7eb',
        marginBottom: '18px',
      },
      tab: {
        flex: 1,
        padding: '10px 14px',
        border: 0,
        borderBottom: '2px solid transparent',
        background: 'transparent',
        color: '#6b7280',
        fontSize: '14px',
        cursor: 'pointer',
        fontWeight: 500,
      },
      tabActive: { color: '#4f46e5', borderBottom: '2px solid #4f46e5' },
      label: { fontSize: '13px', color: '#6b7280', marginBottom: '4px', display: 'block' },
      row: { display: 'flex', gap: '8px', alignItems: 'stretch', marginBottom: '6px' },
      input: {
        flex: 1,
        minWidth: 0,
        height: '40px',
        padding: '0 11px',
        border: '1px solid #d1d5db',
        borderRadius: '8px',
        fontFamily: 'ui-monospace,SFMono-Regular,Menlo,monospace',
        fontSize: '12.5px',
        background: 'var(--dsw-alias-bg-base, #fff)',
        color: 'inherit',
        boxSizing: 'border-box',
      },
      btn: {
        height: '40px',
        padding: '0 16px',
        border: '1px solid #d1d5db',
        borderRadius: '8px',
        background: 'transparent',
        color: 'inherit',
        fontSize: '13px',
        cursor: 'pointer',
        whiteSpace: 'nowrap',
        boxSizing: 'border-box',
      },
      btnSolid: {
        height: '40px',
        padding: '0 16px',
        border: '1px solid #4f46e5',
        borderRadius: '8px',
        background: '#4f46e5',
        color: '#fff',
        fontSize: '13px',
        cursor: 'pointer',
        whiteSpace: 'nowrap',
        boxSizing: 'border-box',
      },
      hint: { fontSize: '12px', color: '#9ca3af', marginTop: '2px' },
      warn: {
        background: '#fffbeb',
        borderLeft: '3px solid #f59e0b',
        padding: '11px 13px',
        borderRadius: '6px',
        fontSize: '13px',
        color: '#92400e',
        margin: '14px 0',
        lineHeight: 1.6,
      },
      ok: {
        background: '#ecfdf5',
        borderLeft: '3px solid #10b981',
        padding: '11px 13px',
        borderRadius: '6px',
        fontSize: '13.5px',
        color: '#065f46',
        margin: '14px 0',
      },
      qa: { fontSize: '12.5px', color: '#6b7280', marginTop: '12px' },
      steps: { margin: '8px 0 14px', paddingLeft: '20px', fontSize: '13.5px' },
      entry: {
        display: 'flex',
        alignItems: 'center',
        padding: '7px 10px',
        borderRadius: '8px',
        border: 0,
        background: 'transparent',
        color: 'inherit',
        cursor: 'pointer',
        width: '100%',
        textAlign: 'left',
        fontSize: '13.5px',
      },
      link: { color: '#4f46e5', textDecoration: 'underline', cursor: 'pointer' },
      timer: { fontSize: '12px', color: '#dc2626', marginTop: '6px' },
    }

    // ── 工具函数 ────────────────────────────────────────────────────────────
    async function api(path, init) {
      const r = await fetch(API_BASE + path, { credentials: 'same-origin', ...init })
      return await r.json()
    }

    async function copyText(text) {
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(text)
          return true
        }
      } catch (e) {}
      try {
        const ta = document.createElement('textarea')
        ta.value = text
        ta.style.position = 'fixed'
        ta.style.opacity = '0'
        document.body.appendChild(ta)
        ta.select()
        const ok = document.execCommand('copy')
        document.body.removeChild(ta)
        return ok
      } catch (e) {
        return false
      }
    }

    function parseCallback(text) {
      const v = String(text == null ? '' : text).trim()
      if (v === '') return { error: '' }
      let qs = v
      const q = v.indexOf('?')
      if (q >= 0) qs = v.slice(q + 1)
      else if (v.charAt(0) === '&') qs = v.slice(1)
      let params
      try {
        params = new URLSearchParams(qs)
      } catch (e) {
        return { error: '这段内容无法解析，请重新复制完整地址' }
      }
      const code = params.get('code')
      const state = params.get('state')
      if (code && state) return { code: code, state: state }
      if (code && !state)
        return { error: '只识别到 code，缺少 state。请复制完整地址（整条地址栏内容）' }
      return { error: '没识别出 code 和 state，请确认复制的是完整地址' }
    }

    // ── 跨设备访问板块 ──────────────────────────────────────────────────────
    function AccessTab() {
      const [info, setInfo] = React.useState(undefined)
      const [err, setErr] = React.useState('')
      const [copied, setCopied] = React.useState('')

      React.useEffect(() => {
        let alive = true
        api('/access-info')
          .then((v) => {
            if (!alive) return
            if (v && v.ok) setInfo(v)
            else setErr('还没有生成访问令牌。请到应用中心停用再启用本应用后重试。')
          })
          .catch(() => alive && setErr('读取访问信息失败，请重试。'))
        return () => {
          alive = false
        }
      }, [])

      const host = typeof window !== 'undefined' ? window.location.hostname : ''
      const link =
        info && info.ok && host
          ? 'http://' + host + ':' + info.port + info.entryPath + '?access_token=' + info.token
          : ''
      const token = info && info.ok ? info.token : ''

      const doCopy = async (which, text) => {
        const ok = await copyText(text)
        setCopied(ok ? which : which + ':fail')
        setTimeout(() => setCopied(''), 1800)
      }
      const label = (which, def) =>
        copied === which ? '已复制' : copied === which + ':fail' ? '请手动复制' : def

      return React.createElement(
        'div',
        null,
        err ? React.createElement('div', { style: S.warn }, err) : null,

        link
          ? React.createElement(
              'div',
              null,
              React.createElement('label', { style: S.label }, '浏览器访问链接'),
              React.createElement(
                'div',
                { style: S.row },
                React.createElement('input', { style: S.input, readOnly: true, value: link }),
                React.createElement(
                  'button',
                  { style: S.btn, onClick: () => doCopy('link', link) },
                  label('link', '复制'),
                ),
              ),
              React.createElement(
                'div',
                { style: S.hint },
                '如公网访问，请将链接内的 IP 改为公网 IP',
              ),
            )
          : null,

        token
          ? React.createElement(
              'div',
              { style: { marginTop: '14px' } },
              React.createElement('label', { style: S.label }, '访问令牌'),
              React.createElement(
                'div',
                { style: S.row },
                React.createElement('input', { style: S.input, readOnly: true, value: token }),
                React.createElement(
                  'button',
                  { style: S.btn, onClick: () => doCopy('token', token) },
                  label('token', '复制'),
                ),
              ),
              React.createElement('div', { style: S.hint }, '如使用软件连接，请在令牌位置输入'),
            )
          : null,

        React.createElement(
          'div',
          { style: S.warn },
          '跨设备登录首次使用下方方式，登录成功后，在令牌有效期内可使用端口直接访问，失效后请重新获取',
        ),

        React.createElement(
          'div',
          { style: S.qa },
          React.createElement('div', null, '有效期 30 天'),
          React.createElement(
            'div',
            { style: { marginTop: '10px' } },
            '⚠️ 此内容等于登录凭证，请妥善使用，一旦泄露，任何人都可能使用它控制本机的 DeepSeek Harness。请在自己信任的设备上使用。',
          ),
          React.createElement(
            'div',
            { style: { marginTop: '12px' } },
            React.createElement('div', null, 'Q：为什么设置令牌？'),
            React.createElement(
              'div',
              null,
              'A：为了保证本机安全，令牌是一道锁，如果没有令牌，任何人都可以通过端口访问 DeepSeek Harness 服务。',
            ),
          ),
        ),
      )
    }

    // ── 账号登录板块 ────────────────────────────────────────────────────────
    function LoginTab() {
      const [authorizeUrl, setAuthorizeUrl] = React.useState('')
      const [expiresAt, setExpiresAt] = React.useState(0)
      const [startErr, setStartErr] = React.useState('')
      const [busy, setBusy] = React.useState(false)
      const [paste, setPaste] = React.useState('')
      const [parsed, setParsed] = React.useState({ error: '' })
      const [msg, setMsg] = React.useState(undefined)
      const [now, setNow] = React.useState(Date.now())

      React.useEffect(() => {
        const t = setInterval(() => setNow(Date.now()), 1000)
        return () => clearInterval(t)
      }, [])

      const secsLeft = expiresAt > 0 ? Math.max(0, Math.floor((expiresAt - now) / 1000)) : 0

      const startLogin = async () => {
        setBusy(true)
        setStartErr('')
        setMsg(undefined)
        try {
          const r = await api('/start-login')
          if (r && r.ok) {
            setAuthorizeUrl(r.authorizeUrl)
            setExpiresAt(typeof r.expiresAt === 'number' ? r.expiresAt : 0)
            window.open(r.authorizeUrl, '_blank', 'noopener,noreferrer')
          } else {
            setStartErr((r && r.reason) || '发起登录失败，请重试')
          }
        } catch (e) {
          setStartErr('发起登录失败：' + e.message)
        } finally {
          setBusy(false)
        }
      }

      const onPaste = (e) => {
        const v = e.target.value
        setPaste(v)
        setParsed(parseCallback(v))
        setMsg(undefined)
      }

      const submit = async () => {
        if (!parsed.code || !parsed.state) return
        setBusy(true)
        setMsg(undefined)
        try {
          const r = await api('/complete-login', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ code: parsed.code, state: parsed.state }),
          })
          if (r && r.ok) {
            setMsg({ kind: 'ok', text: '登录完成，可以关闭本面板了' })
            setPaste('')
            setParsed({ error: '' })
            setAuthorizeUrl('')
          } else {
            setMsg({ kind: 'bad', text: (r && r.reason) || '登录未完成，请重试' })
          }
        } catch (e) {
          setMsg({ kind: 'bad', text: '登录请求失败：' + e.message })
        } finally {
          setBusy(false)
        }
      }

      const canSubmit = !!(parsed.code && parsed.state) && !busy

      return React.createElement(
        'div',
        null,
        React.createElement(
          'p',
          { style: { fontSize: '13.5px', color: '#6b7280', margin: '0 0 10px' } },
          '由于 NAS 设备的特殊性，无法在安全的情况下使用电脑浏览器跳转登录，作者也考虑过牺牲安全性实现便捷，但涉及到账号安全性被我废除。请通过下方途径完成 DeepSeek 账号登录，全程解析在本地完成，虽然麻烦，一切为了安全。',
        ),
        React.createElement(
          'p',
          { style: { fontSize: '13.5px', margin: '0 0 12px' } },
          '或者可以在本机设置里自行配置 API Key',
        ),

        React.createElement('div', { style: { fontSize: '13.5px' } }, '请按下面步骤完成登录：'),
        React.createElement(
          'ol',
          { style: S.steps },
          React.createElement('li', null, '点下面的「开始登录」，会打开 DeepSeek 官方授权页'),
          React.createElement('li', null, '在页面里登录自己的 DeepSeek 账号并授权'),
          React.createElement(
            'li',
            null,
            '授权后页面会变成「无法访问」，这是正常的。点地址栏全选复制（请不要泄露此链接）',
          ),
          React.createElement(
            'li',
            null,
            '回到这里，把复制的内容粘贴到下方输入框，点「完成登录」',
          ),
        ),

        React.createElement(
          'div',
          { style: S.row },
          React.createElement(
            'button',
            {
              style: busy
                ? {
                    ...S.btnSolid,
                    background: '#c7cbd6',
                    borderColor: '#c7cbd6',
                    cursor: 'not-allowed',
                  }
                : S.btnSolid,
              disabled: busy,
              onClick: startLogin,
            },
            busy ? '正在发起…' : '开始登录',
          ),
          authorizeUrl
            ? React.createElement(
                'a',
                {
                  style: { ...S.link, alignSelf: 'center', fontSize: '12.5px' },
                  href: authorizeUrl,
                  target: '_blank',
                  rel: 'noopener noreferrer',
                },
                '重新打开授权页',
              )
            : null,
        ),

        authorizeUrl && secsLeft > 0
          ? React.createElement(
              'div',
              { style: S.timer },
              '授权链接剩余 ' +
                secsLeft +
                ' 秒有效，请尽快完成授权。超时后点「开始登录」重新获取。',
            )
          : null,

        startErr ? React.createElement('div', { style: S.warn }, startErr) : null,

        React.createElement(
          'div',
          { style: { marginTop: '14px' } },
          React.createElement(
            'div',
            { style: S.row },
            React.createElement('input', {
              style: S.input,
              placeholder: '粘贴以 http://127.0.0.1 开头的地址',
              value: paste,
              onChange: onPaste,
            }),
            React.createElement(
              'button',
              {
                style: canSubmit
                  ? S.btnSolid
                  : { ...S.btn, cursor: 'not-allowed', color: '#9ca3af' },
                disabled: !canSubmit,
                onClick: submit,
              },
              busy ? '处理中…' : '完成登录',
            ),
          ),
          React.createElement(
            'div',
            {
              style: {
                fontSize: '12.5px',
                marginTop: '6px',
                color: parsed.error ? '#dc2626' : '#059669',
                minHeight: '18px',
              },
            },
            paste.trim() === ''
              ? ''
              : parsed.error
                ? parsed.error
                : '✓ 已识别，可以点「完成登录」',
          ),
        ),

        msg
          ? React.createElement(
              'div',
              {
                style: {
                  fontSize: '13px',
                  marginTop: '8px',
                  color: msg.kind === 'ok' ? '#059669' : '#dc2626',
                },
              },
              (msg.kind === 'ok' ? '✅ ' : '⚠️ ') + msg.text,
            )
          : null,

        React.createElement(
          'div',
          { style: S.hint },
          '提示：粘贴后会自动识别，格式不对会立刻提示',
        ),
      )
    }

    // ── 主面板 ──────────────────────────────────────────────────────────────
    function Panel(props) {
      const [tab, setTab] = React.useState('access')

      React.useEffect(() => {
        const onKey = (e) => {
          if (e.key === 'Escape') props.onClose()
        }
        window.addEventListener('keydown', onKey)
        return () => window.removeEventListener('keydown', onKey)
      }, [props])

      const tabBtn = (key, text) =>
        React.createElement(
          'button',
          {
            style: tab === key ? { ...S.tab, ...S.tabActive } : S.tab,
            onClick: () => setTab(key),
          },
          text,
        )

      return React.createElement(
        'div',
        {
          style: S.overlay,
          onClick: (e) => e.target === e.currentTarget && props.onClose(),
        },
        React.createElement(
          'div',
          { style: S.dialog, role: 'dialog', 'aria-modal': 'true' },
          React.createElement(
            'div',
            { style: S.tabs },
            tabBtn('access', '跨设备访问'),
            tabBtn('login', '账号登录'),
          ),
          tab === 'access'
            ? React.createElement(AccessTab, null)
            : React.createElement(LoginTab, null),
          React.createElement(
            'div',
            { style: { textAlign: 'right', marginTop: '20px' } },
            React.createElement('button', { style: S.btn, onClick: props.onClose }, '关闭'),
          ),
        ),
      )
    }

    // ── 侧栏入口（纯文字，无图标）──────────────────────────────────────────
    function EntryButton(props) {
      const [hover, setHover] = React.useState(false)
      return React.createElement(
        'button',
        {
          style: {
            ...S.entry,
            background: hover
              ? 'var(--dsw-alias-interactive-bg-hover, rgba(0,0,0,.05))'
              : 'transparent',
          },
          onClick: props.onClick,
          onMouseEnter: () => setHover(true),
          onMouseLeave: () => setHover(false),
          title: '注意事项',
        },
        React.createElement('span', null, '注意事项'),
      )
    }

    function AccessEntry() {
      const [open, setOpen] = React.useState(false)
      return React.createElement(
        React.Fragment,
        null,
        React.createElement(EntryButton, { onClick: () => setOpen(true) }),
        open ? React.createElement(Panel, { onClose: () => setOpen(false) }) : null,
      )
    }

    // ── 插件入口 ────────────────────────────────────────────────────────────
    var inject = ['slots']

    function apply(ctx) {
      ctx.slots.inject(SLOT, function () {
        return ctx.slots.register(
          { name: SLOT, id: 'dsh-fnos-panel-access', order: 10 },
          AccessEntry,
        )
      })
    }

    module.exports.apply = apply
    module.exports.inject = inject
    return module.exports
  },
})
