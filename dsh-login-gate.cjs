/*
 * dsh-login-gate.cjs - a login gate in front of the DeepSeek Harness Web UI.
 *
 * What it does
 *   Listens on GATE_HOST:GATE_PORT (default 127.0.0.1:8080) and forwards every
 *   authenticated request to the real harness at UPSTREAM (127.0.0.1:3080).
 *   Nothing reaches the harness - not the pages, not /api, not the WebSocket -
 *   until the visitor has logged in.
 *
 *   Browsers get an HTML login page; non-browser clients (curl, scripts) get an
 *   HTTP Basic challenge, so both work. A successful login issues an HttpOnly
 *   session cookie, which is what makes the WebSocket upgrade work too: a
 *   browser cannot attach an Authorization header to a WebSocket handshake, but
 *   it does send cookies.
 *
 * Why the request headers are rewritten
 *   The harness protects /api with a browser-trust fence: a request whose
 *   Origin/Host authority is not trusted is answered with 403. Since the browser
 *   talks to this proxy on a different port, Host and Origin are rewritten to
 *   the upstream authority so the harness sees a trusted same-origin request.
 *
 * Credentials
 *   No plaintext password is ever written to disk - only a salted scrypt hash:
 *
 *     { version: 2, user, kdf: { name, N, r, p, keylen }, salt, hash, updatedAt }
 *
 *   Registration happens in the BROWSER, not the terminal. With no credentials
 *   the gate starts in setup mode and serves a registration form. That entry is
 *   guarded by a one-time token printed at startup and closes permanently once
 *   registration succeeds, so nobody can claim the gate first. The token is
 *   required even for loopback requests: a cross-site POST from a page open in
 *   the user's own browser also arrives from 127.0.0.1, so loopback alone is
 *   not proof of identity.
 *
 *     http://127.0.0.1:8080/                  -> redirects to the form
 *     .../__gate/setup?token=<printed token>  -> the printed link
 *
 *   A fresh 16-byte salt per write means two identical passwords never produce
 *   the same file content. Optional command-line equivalents:
 *
 *     node dsh-login-gate.cjs --setup        (re-open web registration)
 *     node dsh-login-gate.cjs --init         (set credentials in the terminal)
 *     node dsh-login-gate.cjs --init-only    (set credentials, then exit)
 *
 *   A legacy config that still holds a plaintext "pass" field is migrated to
 *   the salted format automatically.
 *
 * Configuration
 *   DSH_GATE_USER / DSH_GATE_PASS   override the stored credentials for this run
 *                                   (both must be set; if no config exists yet
 *                                   they are used to initialize it)
 *   DSH_GATE_HOST / DSH_GATE_PORT   listen address   (default 127.0.0.1:8080)
 *   DSH_GATE_UPSTREAM               upstream origin  (default http://127.0.0.1:3080)
 *   DSH_GATE_INIT_FROM_STDIN=1      allow non-interactive setup by piping three
 *                                   lines (username, password, confirmation).
 *                                   Automation only: a pipe is not a TTY, so the
 *                                   password cannot be masked.
 *
 * Stop with Ctrl+C, or kill the process running this file.
 */

const http = require('node:http')
const net = require('node:net')
const fs = require('node:fs')
const path = require('node:path')
const crypto = require('node:crypto')

const CONFIG_PATH = path.join(__dirname, 'dsh-login-gate.config.json')
const CONFIG_VERSION = 2
const DEFAULT_USER = 'dsh'
const MIN_PASSWORD_LENGTH = 8
const DEFAULT_KDF = { name: 'scrypt', N: 16384, r: 8, p: 1, keylen: 64 }

const GATE_HOST = process.env.DSH_GATE_HOST || '127.0.0.1'
const GATE_PORT = Number(process.env.DSH_GATE_PORT || 8080)
const UPSTREAM = new URL(process.env.DSH_GATE_UPSTREAM || 'http://127.0.0.1:3080')

const config = { host: GATE_HOST, port: GATE_PORT, upstream: UPSTREAM }
const UPSTREAM_ORIGIN = UPSTREAM.origin                  // http://127.0.0.1:3080
const UPSTREAM_AUTHORITY = UPSTREAM.host                 // 127.0.0.1:3080
const CLIENT_AUTHORITY = config.host + ':' + config.port // what the browser sees
const COOKIE_NAME = 'dsh_gate'
const SESSION_TTL_MS = 12 * 60 * 60 * 1000

/** Active credentials: a stored hash record, optionally overridden by env vars. */
let active = { user: DEFAULT_USER, record: undefined, source: 'unset', env: undefined }

/**
 * Web registration mode: the gate serves a first-run form instead of the app.
 * `setupToken` is a one-time secret printed at startup; it is required on every
 * setup request, because a cross-site POST from a page in the user's own
 * browser also arrives from 127.0.0.1 - loopback is not a trust signal here.
 */
let setupMode = false
let setupToken

// ------------------------------------------------------- salted credential store

function deriveKey(password, salt, kdf) {
  const params = kdf !== undefined && kdf !== null && kdf.name === 'scrypt' ? kdf : DEFAULT_KDF
  return crypto.scryptSync(password, salt, params.keylen, { N: params.N, r: params.r, p: params.p })
}

/** A fresh random salt per call, so equal passwords yield different files. */
function writeCredentials(user, password) {
  const salt = crypto.randomBytes(16)
  const hash = deriveKey(password, salt, DEFAULT_KDF)
  const document = {
    version: CONFIG_VERSION,
    user,
    kdf: DEFAULT_KDF,
    salt: salt.toString('base64'),
    hash: hash.toString('base64'),
    updatedAt: new Date().toISOString(),
    note: 'Salted scrypt hash only - there is no plaintext password in this file. Run with --init to change credentials.',
  }
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(document, null, 2) + '\n', { mode: 0o600 })
  return document
}

function verifyPassword(password, record) {
  if (typeof password !== 'string' || password.length === 0) return false
  if (record === undefined || record === null) return false
  if (typeof record.salt !== 'string' || typeof record.hash !== 'string') return false
  const salt = Buffer.from(record.salt, 'base64')
  const expected = Buffer.from(record.hash, 'base64')
  // An empty or truncated salt/hash can never authenticate anyone.
  if (salt.length < 8 || expected.length < 16) return false
  let actual
  try {
    actual = deriveKey(password, salt, record.kdf)
  } catch (error) {
    return false
  }
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected)
}

/** Classify the config file without throwing, so startup can always explain itself. */
function readConfigState() {
  if (!fs.existsSync(CONFIG_PATH)) return { status: 'missing' }
  let raw
  try {
    raw = fs.readFileSync(CONFIG_PATH, 'utf8')
  } catch (error) {
    return { status: 'corrupt', reason: error.message }
  }
  let document
  try {
    document = JSON.parse(raw)
  } catch (error) {
    return { status: 'corrupt', reason: error.message }
  }
  if (document === null || typeof document !== 'object') {
    return { status: 'corrupt', reason: 'not a JSON object' }
  }
  const hasHash = typeof document.hash === 'string' && document.hash.length > 0
  const hasSalt = typeof document.salt === 'string' && document.salt.length > 0
  if (hasHash && hasSalt) return { status: 'ok', document }
  // Legacy format: a plaintext "pass" field (an EMPTY one is deliberately not
  // migrated - that is exactly the "empty password accepted" hole).
  if (typeof document.pass === 'string' && document.pass.length > 0) {
    return { status: 'legacy', document }
  }
  return { status: 'invalid', reason: 'no usable hash/salt and no legacy plaintext password' }
}

// ------------------------------------------------------------- interactive input

/** Read one line from a TTY, optionally masking what is typed. */
function askTty(question, hidden) {
  return new Promise((resolve, reject) => {
    const stdin = process.stdin
    const stdout = process.stdout
    stdout.write(question)
    stdin.setRawMode(true)
    stdin.resume()
    let buffer = ''
    let skippingEscape = false
    const cleanup = () => {
      stdin.removeListener('data', onData)
      stdin.setRawMode(false)
      stdin.pause()
    }
    const onData = (chunk) => {
      for (const char of chunk.toString('utf8')) {
        if (skippingEscape) {
          if (/[A-Za-z~]/.test(char)) skippingEscape = false
          continue
        }
        if (char === '\u001b') { skippingEscape = true; continue }   // arrow keys etc.
        if (char === '\u0003') {                                     // Ctrl+C
          cleanup(); stdout.write('\n'); reject(new Error('cancelled by user')); return
        }
        if (char === '\r' || char === '\n') {
          cleanup(); stdout.write('\n'); resolve(buffer); return
        }
        if (char === '\u007f' || char === '\b') {
          if (buffer.length > 0) { buffer = buffer.slice(0, -1); stdout.write('\b \b') }
          continue
        }
        if (char < ' ') continue
        buffer += char
        stdout.write(hidden ? '*' : char)
      }
    }
    stdin.on('data', onData)
  })
}

/** Line reader over a pipe, used only when DSH_GATE_INIT_FROM_STDIN=1. */
function makePipeReader() {
  let buffer = ''
  const pending = []
  let waiter
  process.stdin.setEncoding('utf8')
  process.stdin.on('data', (chunk) => {
    buffer += chunk
    let index
    while ((index = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, index).replace(/\r$/, '')
      buffer = buffer.slice(index + 1)
      if (waiter !== undefined) { const resume = waiter; waiter = undefined; resume(line) } else pending.push(line)
    }
  })
  process.stdin.resume()
  return (question) => {
    process.stdout.write(question)
    if (pending.length > 0) return Promise.resolve(pending.shift())
    return new Promise((resolve) => { waiter = resolve })
  }
}

let pipeReader

function ask(question, options = {}) {
  const hidden = options.hidden === true
  const stdin = process.stdin
  if (stdin.isTTY === true && typeof stdin.setRawMode === 'function') {
    return askTty(question, hidden)
  }
  if (process.env.DSH_GATE_INIT_FROM_STDIN === '1') {
    if (pipeReader === undefined) pipeReader = makePipeReader()
    return pipeReader(question)
  }
  return Promise.reject(new Error(
    '需要交互式终端来设置凭据，但当前标准输入不是 TTY。\n' +
    '  · 在终端里手动执行一次：node ' + path.basename(__filename) + ' --init\n' +
    '  · 或设置 DSH_GATE_USER 与 DSH_GATE_PASS 环境变量以非交互方式初始化\n' +
    '  · 或设置 DSH_GATE_INIT_FROM_STDIN=1 并用管道传入三行（用户名、密码、确认密码）',
  ))
}

async function setupCredentials(reason, currentUser) {
  console.log('')
  console.log('== ' + reason + ' ==')
  console.log('请设置登录门禁的用户名和密码（只保存加盐哈希，不保存明文）')
  console.log('配置文件: ' + CONFIG_PATH)
  console.log('')
  for (let attempt = 1; attempt <= 3; attempt++) {
    const answer = (await ask('用户名 [' + (currentUser || DEFAULT_USER) + ']: ')).trim()
    const user = answer === '' ? (currentUser || DEFAULT_USER) : answer
    const password = await ask('密码（至少 ' + MIN_PASSWORD_LENGTH + ' 位，输入不回显）: ', { hidden: true })
    if (password.length < MIN_PASSWORD_LENGTH) {
      console.log('  ✗ 密码太短，至少 ' + MIN_PASSWORD_LENGTH + ' 位。\n')
      continue
    }
    const confirmation = await ask('再次输入密码: ', { hidden: true })
    if (password !== confirmation) {
      console.log('  ✗ 两次输入不一致，请重试。\n')
      continue
    }
    const document = writeCredentials(user, password)
    console.log('')
    console.log('✓ 凭据已保存：user=' + user + '（密码存为 scrypt 加盐哈希）')
    return { user, record: document, source: 'setup', env: undefined }
  }
  throw new Error('凭据设置失败：连续 3 次输入无效。')
}

function printHelp() {
  console.log('用法: node ' + path.basename(__filename) + ' [--setup|--init|--init-only] [--help]')
  console.log('')
  console.log('  (无参数)    启动登录门禁；若尚无配置则进入【网页注册】模式')
  console.log('  --setup     即使已有凭据也强制进入网页注册模式（重新注册）')
  console.log('  --init      改用命令行设置用户名和密码，然后启动监听')
  console.log('  --init-only 只设置用户名和密码并退出，不启动监听')
  console.log('  --help      显示本帮助')
  console.log('')
  console.log('网页注册: 启动后在浏览器打开 http://<host>:<port>/ ，')
  console.log('          或使用控制台打印的带一次性 token 的注册链接。')
  console.log('')
  console.log('环境变量: DSH_GATE_HOST, DSH_GATE_PORT, DSH_GATE_UPSTREAM,')
  console.log('          DSH_GATE_USER, DSH_GATE_PASS, DSH_GATE_INIT_FROM_STDIN')
}

/** token -> expiry timestamp */
const sessions = new Map()

function issueSession() {
  const token = crypto.randomBytes(32).toString('hex')
  sessions.set(token, Date.now() + SESSION_TTL_MS)
  return token
}

function sessionValid(token) {
  if (typeof token !== 'string') return false
  const expiry = sessions.get(token)
  if (expiry === undefined) return false
  if (expiry < Date.now()) {
    sessions.delete(token)
    return false
  }
  return true
}

function parseCookies(header) {
  const out = {}
  if (typeof header !== 'string') return out
  for (const part of header.split(';')) {
    const index = part.indexOf('=')
    if (index < 0) continue
    out[part.slice(0, index).trim()] = decodeURIComponent(part.slice(index + 1).trim())
  }
  return out
}

/** Constant-time comparison so the gate does not leak credential length/prefix. */
function safeEqual(a, b) {
  const left = Buffer.from(String(a))
  const right = Buffer.from(String(b))
  if (left.length !== right.length) return false
  return crypto.timingSafeEqual(left, right)
}

function basicCredentials(header) {
  if (typeof header !== 'string') return undefined
  const match = /^Basic[ \t]+([A-Za-z0-9+/=]+)$/i.exec(header.trim())
  if (match === null) return undefined
  const decoded = Buffer.from(match[1], 'base64').toString('utf8')
  const separator = decoded.indexOf(':')
  if (separator < 0) return undefined
  return { user: decoded.slice(0, separator), pass: decoded.slice(separator + 1) }
}

/** Verify against the env override when present, otherwise against the hash. */
function credentialsOk(pair) {
  if (pair === undefined || !safeEqual(pair.user, active.user)) return false
  if (active.env !== undefined) return safeEqual(pair.pass, active.env)
  return verifyPassword(pair.pass, active.record)
}

/** Cookie session, or valid Basic credentials (which also mints a session). */
function authenticate(req) {
  const cookies = parseCookies(req.headers.cookie)
  if (sessionValid(cookies[COOKIE_NAME])) return { ok: true, mint: false }
  if (credentialsOk(basicCredentials(req.headers.authorization))) return { ok: true, mint: true }
  return { ok: false, mint: false }
}

function sessionCookie(token) {
  // No Secure flag: the gate is expected to run on loopback or behind TLS.
  return COOKIE_NAME + '=' + token + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + Math.floor(SESSION_TTL_MS / 1000)
}

function escapeHtml(value) {
  return String(value === undefined || value === null ? '' : value)
    .replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
}

const PAGE_CSS = `
  :root { color-scheme: dark }
  body { margin:0; min-height:100vh; display:grid; place-items:center;
         background:#0f1115; color:#e6e6e6;
         font:15px/1.5 ui-sans-serif,system-ui,"Segoe UI",sans-serif }
  form { width:min(380px,92vw); padding:28px; border:1px solid #262b36; border-radius:14px;
         background:#151922; box-shadow:0 18px 50px rgba(0,0,0,.45) }
  h1 { margin:0 0 4px; font-size:19px }
  p.sub { margin:0 0 20px; color:#8b93a7; font-size:13px }
  label { display:block; margin:14px 0 6px; font-size:13px; color:#a9b1c3 }
  input { width:100%; box-sizing:border-box; padding:10px 12px; border-radius:9px;
          border:1px solid #2c3242; background:#0e1219; color:#e6e6e6; font:inherit }
  input:focus { outline:none; border-color:#4c8dff }
  button { width:100%; margin-top:22px; padding:11px; border:0; border-radius:9px;
           background:#2f6feb; color:#fff; font:600 15px/1 inherit; cursor:pointer }
  button:hover { background:#3b7bf5 }
  .err { margin-top:16px; padding:9px 12px; border-radius:9px;
         background:#3a1a1e; border:1px solid #6b2b33; color:#ffb4b4; font-size:13px }
  .note { margin-top:18px; color:#6f7789; font-size:12px; line-height:1.6 }
`

/** `no-referrer` keeps the one-time setup token out of outbound Referer headers. */
function pageShell(title, content) {
  return `<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>${escapeHtml(title)}</title>
<style>${PAGE_CSS}</style></head>
<body>
${content}
</body></html>`
}

function loginPage(next, failed) {
  return pageShell('DSH - 需要登录', `  <form method="POST" action="/__gate/login">
    <h1>DeepSeek Harness</h1>
    <p class="sub">请登录后继续访问。</p>
    <input type="hidden" name="next" value="${escapeHtml(next)}">
    <label for="user">用户名</label>
    <input id="user" name="user" autocomplete="username" autofocus>
    <label for="pass">密码</label>
    <input id="pass" name="pass" type="password" autocomplete="current-password">
    <button type="submit">登录</button>
    ${failed ? '<div class="err">用户名或密码不正确。</div>' : ''}
  </form>`)
}

function setupPage(token, error, previousUser) {
  return pageShell('DSH - 首次注册', `  <form method="POST" action="/__gate/setup">
    <h1>首次注册</h1>
    <p class="sub">设置登录门禁的用户名和密码。</p>
    <input type="hidden" name="token" value="${escapeHtml(token)}">
    <label for="user">用户名</label>
    <input id="user" name="user" value="${escapeHtml(previousUser || DEFAULT_USER)}" autocomplete="username" autofocus>
    <label for="pass">密码（至少 ${MIN_PASSWORD_LENGTH} 位）</label>
    <input id="pass" name="pass" type="password" autocomplete="new-password">
    <label for="confirm">再次输入密码</label>
    <input id="confirm" name="confirm" type="password" autocomplete="new-password">
    <button type="submit">创建并登录</button>
    ${error ? '<div class="err">' + escapeHtml(error) + '</div>' : ''}
    <p class="note">密码只以加盐 scrypt 哈希保存，不会写入明文。<br>注册成功后本入口立即关闭。</p>
  </form>`)
}

function send(res, status, headers, body) {
  res.writeHead(status, headers)
  res.end(body)
}

function sendUnauthorized(req, res) {
  const wantsHtml = String(req.headers.accept || '').includes('text/html')
  if (wantsHtml) {
    send(res, 200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }, loginPage(req.url || '/', false))
    return
  }
  send(res, 401, {
    'WWW-Authenticate': 'Basic realm="DeepSeek Harness", charset="UTF-8"',
    'Content-Type': 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store',
  }, '401 Unauthorized - sign in at ' + UPSTREAM_ORIGIN + ' or use -u user:pass\n')
}

// ------------------------------------------------------------ web registration

function isLoopbackRequest(req) {
  const address = req.socket === undefined ? undefined : req.socket.remoteAddress
  return address === '127.0.0.1' || address === '::1' || address === '::ffff:127.0.0.1'
}

function setupTokenOk(url, body) {
  const provided = url.searchParams.get('token') || (body === undefined ? undefined : body.get('token'))
  if (typeof provided !== 'string' || provided.length === 0) return false
  if (typeof setupToken !== 'string') return false
  return safeEqual(provided, setupToken)
}

function setupUrl() {
  const host = config.host === '0.0.0.0' || config.host === '::' ? '127.0.0.1' : config.host
  return 'http://' + host + ':' + config.port + '/__gate/setup?token=' + setupToken
}

async function handleSetupRequest(req, res, url) {
  const isFormPath = url.pathname === '/__gate/setup'
  const noStore = { 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' }

  if (isFormPath && req.method === 'GET') {
    if (!setupTokenOk(url, undefined)) {
      // A local browser may follow the redirect to pick up the token; a remote
      // client must already hold the link printed at startup.
      if (isLoopbackRequest(req)) {
        res.writeHead(302, { Location: '/__gate/setup?token=' + setupToken, ...noStore })
        res.end()
        return
      }
      send(res, 403, { 'Content-Type': 'text/plain; charset=utf-8', ...noStore },
        '403 - 注册需要启动时打印的一次性 token。\n' +
        '本机请直接打开 http://127.0.0.1:' + config.port + '/ ，或在控制台复制完整注册链接。\n')
      return
    }
    send(res, 200, { 'Content-Type': 'text/html; charset=utf-8', ...noStore }, setupPage(setupToken, undefined))
    return
  }

  if (isFormPath && req.method === 'POST') {
    const body = new URLSearchParams(await readBody(req))
    if (!setupTokenOk(url, body)) {
      send(res, 403, { 'Content-Type': 'text/plain; charset=utf-8', ...noStore },
        '403 - token 无效或缺失，注册被拒绝。\n')
      return
    }
    const user = (body.get('user') || '').trim() || DEFAULT_USER
    const password = body.get('pass') || ''
    const confirmation = body.get('confirm') || ''
    const reject = (message) => send(res, 400,
      { 'Content-Type': 'text/html; charset=utf-8', ...noStore }, setupPage(setupToken, message, user))

    if (password.length < MIN_PASSWORD_LENGTH) {
      reject('密码至少需要 ' + MIN_PASSWORD_LENGTH + ' 位。')
      return
    }
    if (password !== confirmation) {
      reject('两次输入的密码不一致。')
      return
    }
    const document = writeCredentials(user, password)
    active = { user, record: document, source: 'web registration', env: undefined }
    setupMode = false
    setupToken = undefined
    console.log(new Date().toISOString() + ' 网页注册完成：user=' + user + '，注册入口已关闭')
    res.writeHead(302, { Location: '/', 'Set-Cookie': sessionCookie(issueSession()), ...noStore })
    res.end()
    return
  }

  // Any other path while registration is open: send the visitor to the form.
  if (isLoopbackRequest(req)) {
    res.writeHead(302, { Location: '/__gate/setup?token=' + setupToken, ...noStore })
    res.end()
    return
  }
  send(res, 403, { 'Content-Type': 'text/plain; charset=utf-8', ...noStore },
    '403 - 门禁尚未注册。请在服务器本机打开 http://127.0.0.1:' + config.port + '/，\n' +
    '或使用启动时打印的带 token 注册链接。\n')
}

/** Copy client headers upstream, rewriting the authority the harness trusts. */
function upstreamHeaders(rawHeaders) {
  const headers = {}
  for (let i = 0; i < rawHeaders.length; i += 2) {
    const name = rawHeaders[i]
    const value = rawHeaders[i + 1]
    const lower = name.toLowerCase()
    if (lower === 'host') { headers[name] = UPSTREAM_AUTHORITY; continue }
    if (lower === 'origin') { headers[name] = UPSTREAM_ORIGIN; continue }
    if (lower === 'referer' || lower === 'referrer') {
      headers[name] = String(value).replace('http://' + CLIENT_AUTHORITY, UPSTREAM_ORIGIN)
      continue
    }
    // Node joins repeated headers; keep the first value for the rest.
    if (headers[name] === undefined) headers[name] = value
  }
  headers['x-forwarded-host'] = CLIENT_AUTHORITY
  headers['x-forwarded-proto'] = 'http'
  return headers
}

function proxyHttp(req, res) {
  const target = http.request({
    host: config.upstream.hostname,
    port: config.upstream.port,
    method: req.method,
    path: req.url,
    headers: upstreamHeaders(req.rawHeaders),
  }, (upstreamRes) => {
    res.writeHead(upstreamRes.statusCode || 502, upstreamRes.headers)
    upstreamRes.pipe(res)
  })
  target.on('error', (error) => {
    if (res.headersSent) { res.destroy(); return }
    send(res, 502, { 'Content-Type': 'text/plain; charset=utf-8' },
      '502 Bad Gateway - upstream ' + UPSTREAM_ORIGIN + ' is not reachable (' + error.code + ')\n')
  })
  req.pipe(target)
}

function readBody(req, limit = 8192) {
  return new Promise((resolve) => {
    let size = 0
    const chunks = []
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > limit) { req.destroy(); resolve(''); return }
      chunks.push(chunk)
    })
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
  })
}

function safeNext(value) {
  if (typeof value !== 'string') return '/'
  if (!value.startsWith('/') || value.startsWith('//')) return '/'
  return value
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || '/', UPSTREAM_ORIGIN)

  if (url.pathname === '/__gate/health') {
    send(res, 200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
      JSON.stringify({ ok: true, upstream: UPSTREAM_ORIGIN, sessions: sessions.size, setup: setupMode }))
    return
  }

  if (setupMode) {
    await handleSetupRequest(req, res, url)
    return
  }

  if (url.pathname === '/__gate/login' && req.method === 'POST') {
    const body = new URLSearchParams(await readBody(req))
    const next = safeNext(body.get('next'))
    if (credentialsOk({ user: body.get('user') || '', pass: body.get('pass') || '' })) {
      console.log(new Date().toISOString() + ' login ok -> ' + next)
      res.writeHead(302, { Location: next, 'Set-Cookie': sessionCookie(issueSession()), 'Cache-Control': 'no-store' })
      res.end()
      return
    }
    console.log(new Date().toISOString() + ' login FAILED')
    send(res, 401, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }, loginPage(next, true))
    return
  }

  if (url.pathname === '/__gate/logout') {
    const cookies = parseCookies(req.headers.cookie)
    if (typeof cookies[COOKIE_NAME] === 'string') sessions.delete(cookies[COOKIE_NAME])
    res.writeHead(302, {
      Location: '/',
      'Set-Cookie': COOKIE_NAME + '=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0',
      'Cache-Control': 'no-store',
    })
    res.end()
    return
  }

  const auth = authenticate(req)
  if (!auth.ok) {
    sendUnauthorized(req, res)
    return
  }
  if (auth.mint) {
    // Basic succeeded: also plant the cookie so the WebSocket handshake passes.
    res.setHeader('Set-Cookie', sessionCookie(issueSession()))
  }
  proxyHttp(req, res)
})

server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url || '/', UPSTREAM_ORIGIN)
  if (url.pathname.startsWith('/__gate/')) { socket.destroy(); return }
  const auth = authenticate(req)
  if (!auth.ok) {
    socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n')
    socket.destroy()
    return
  }
  const upstream = net.connect(config.upstream.port, config.upstream.hostname, () => {
    const out = []
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      const name = req.rawHeaders[i]
      const value = req.rawHeaders[i + 1]
      const lower = name.toLowerCase()
      if (lower === 'host') { out.push(name, UPSTREAM_AUTHORITY); continue }
      if (lower === 'origin') { out.push(name, UPSTREAM_ORIGIN); continue }
      out.push(name, value)
    }
    let handshake = 'GET ' + req.url + ' HTTP/1.1\r\n'
    for (let i = 0; i < out.length; i += 2) handshake += out[i] + ': ' + out[i + 1] + '\r\n'
    handshake += '\r\n'
    upstream.write(handshake)
    if (head !== undefined && head.length > 0) upstream.write(head)
    upstream.pipe(socket)
    socket.pipe(upstream)
  })
  upstream.on('error', () => socket.destroy())
  socket.on('error', () => upstream.destroy())
  socket.on('close', () => upstream.destroy())
})

function startServer() {
  server.listen(config.port, config.host, () => {
    console.log('dsh login gate listening on http://' + config.host + ':' + config.port)
    console.log('  upstream : ' + UPSTREAM_ORIGIN)
    console.log('  config   : ' + CONFIG_PATH)
    if (setupMode) {
      console.log('  user     : (尚未注册)')
      console.log('')
      console.log('[gate] 尚未设置凭据 —— 已进入网页注册模式，请在浏览器打开：')
      console.log('[gate]   ' + setupUrl())
      console.log('[gate] 注册成功后入口自动关闭；本机也可直接打开 http://127.0.0.1:' + config.port + '/ 跳转过去。')
      console.log('')
    } else {
      console.log('  user     : ' + active.user + '  (' + active.source + ')')
      console.log('  open     : http://' + config.host + ':' + config.port + '/')
    }
    if (config.host !== '127.0.0.1' && config.host !== 'localhost' && config.host !== '::1') {
      console.warn('[gate] 警告：监听在 ' + config.host + ' 且未启用 TLS ——')
      console.warn('[gate] 登录表单与 Basic 凭据会以明文经过网络，请改用 HTTPS 或仅经 VPN/隧道访问。')
    }
  })
}

async function main() {
  if (process.argv.includes('--help') || process.argv.includes('-h')) {
    printHelp()
    return
  }

  const forceInit = process.argv.includes('--init') || process.argv.includes('--init-only')
  const initOnly = process.argv.includes('--init-only')

  // --setup: re-open the browser registration entry even when credentials exist.
  if (process.argv.includes('--setup')) {
    setupMode = true
    setupToken = crypto.randomBytes(16).toString('hex')
    startServer()
    return
  }
  const envUser = process.env.DSH_GATE_USER
  const envPass = process.env.DSH_GATE_PASS
  const hasEnv = typeof envUser === 'string' && envUser.length > 0 &&
                 typeof envPass === 'string' && envPass.length > 0

  const state = readConfigState()
  let needsSetup = false
  let reason = ''

  const backupBroken = () => {
    const backup = CONFIG_PATH + '.broken-' + Date.now()
    try {
      fs.renameSync(CONFIG_PATH, backup)
      console.error('[gate] 配置不可用（' + (state.reason || state.status) + '），已备份到 ' + backup)
    } catch (error) {
      console.error('[gate] 配置不可用（' + (state.reason || state.status) + '），备份失败：' + error.message)
    }
  }

  if (forceInit) {
    // Keep the stored username as the prompt default; preserve a broken file.
    if (state.status === 'corrupt' || state.status === 'invalid') backupBroken()
    needsSetup = true
    reason = '重新设置凭据（--init）'
  } else if (state.status === 'ok') {
    active = { user: state.document.user || DEFAULT_USER, record: state.document, source: 'config', env: undefined }
  } else if (state.status === 'legacy') {
    const user = typeof state.document.user === 'string' && state.document.user.length > 0
      ? state.document.user : DEFAULT_USER
    const document = writeCredentials(user, state.document.pass)
    console.log('[gate] 检测到旧版明文密码，已迁移为加盐 scrypt 哈希（user=' + user + '）。')
    console.log('[gate] 如需更换用户名/密码：node ' + path.basename(__filename) + ' --init，然后重启门禁。')
    active = { user, record: document, source: 'config (migrated)', env: undefined }
  } else if (state.status === 'missing') {
    needsSetup = true
    reason = '首次初始化'
  } else {
    backupBroken()
    needsSetup = true
    reason = '配置需要重新设置'
  }

  if (needsSetup) {
    if (hasEnv) {
      const document = writeCredentials(envUser, envPass)
      console.log('[gate] 已用环境变量初始化凭据：user=' + envUser + '（写入的是加盐哈希）')
      active = { user: envUser, record: document, source: 'env (initialized)', env: undefined }
    } else if (forceInit) {
      // Explicit CLI path only: --init / --init-only.
      const previousUser = state.document !== undefined && typeof state.document.user === 'string'
        ? state.document.user : undefined
      try {
        active = await setupCredentials(reason, previousUser)
      } catch (error) {
        console.error('[gate] ' + error.message)
        process.exitCode = 1
        return
      }
    } else {
      // Default first run: register through the browser, not the terminal.
      setupMode = true
      setupToken = crypto.randomBytes(16).toString('hex')
      console.log('[gate] ' + reason + '：改用网页注册（不需要在命令行输入凭据）。')
    }
  } else if (hasEnv) {
    active = { user: envUser, record: active.record, source: 'env (override)', env: envPass }
    console.log('[gate] 本次运行使用 DSH_GATE_USER/DSH_GATE_PASS 覆盖已存储的凭据。')
  }

  if (initOnly) {
    console.log('[gate] --init-only：凭据已写入，未启动监听。')
    console.log('[gate] 运行 node ' + path.basename(__filename) + ' 即可启动门禁。')
    return
  }

  startServer()
}

process.on('SIGINT', () => { console.log('shutting down'); process.exit(0) })
process.on('SIGTERM', () => { console.log('shutting down'); process.exit(0) })

main().catch((error) => {
  console.error('[gate] 启动失败：' + (error && error.stack ? error.stack : error))
  process.exitCode = 1
})
