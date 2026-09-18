# DSH 登录门禁（dsh-login-gate）

给 DeepSeek Harness 的 Web 界面套一层**用户名/密码登录门禁**。

`dsh web` 本身只监听 `127.0.0.1`，并用「启动时打印的带令牌 URL」保护界面。本门禁在此之上提供一个真正的登录边界：**未登录时，网页、`/api` 与 WebSocket 一律无法到达 harness**。

```
浏览器 ──► http://127.0.0.1:8080        ──► http://127.0.0.1:3080
           dsh-login-gate.cjs                 dsh web (harness)
           ① 未登录：401 / 登录页 / 注册页
           ② 登录后：HttpOnly 会话 Cookie 放行
```

- **零依赖**：只用 Node.js 内置模块（`node:http` / `node:net` / `node:crypto` / `node:fs` / `node:path`），无需 `npm install`。
- **单文件**：所有逻辑都在 `dsh-login-gate.cjs`。
- **密码不落明文**：磁盘上只有加盐 scrypt 哈希。

---

## 快速开始

```powershell
node C:\Users\abstudio\Documents\dsh-login-gate.cjs
```

首次启动时没有凭据，门禁会进入**网页注册模式**并打印：

```
[gate] 尚未设置凭据 —— 已进入网页注册模式，请在浏览器打开：
[gate]   http://127.0.0.1:8080/__gate/setup?token=xxxxxxxx
```

用浏览器打开 **`http://127.0.0.1:8080/`**（会自动跳转到带 token 的注册页），填写用户名、密码（≥8 位）、确认密码，点「创建并登录」即可 —— 注册成功会直接登录并跳转到 harness 界面。

> 注册成功后入口**永久关闭**，此时才会生成 `dsh-login-gate.config.json`。

停止：在该终端按 `Ctrl+C`，或结束对应的 node 进程。

---

## 命令行参数

| 命令 | 作用 |
| --- | --- |
| `node dsh-login-gate.cjs` | 启动门禁。无配置时进入**网页注册**模式；已有配置则直接服务 |
| `--setup` | 即使已有凭据，也强制进入网页注册模式（**改密码走这里**） |
| `--init` | 改用**命令行**设置用户名/密码，然后启动监听（需要 TTY） |
| `--init-only` | 只设置用户名/密码并退出，不启动监听（便于随后由别的方式托管服务） |
| `--help` / `-h` | 显示帮助 |

## 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `DSH_GATE_HOST` | `127.0.0.1` | 监听地址。设为 `0.0.0.0` 可对外提供服务（**务必配合 HTTPS 或 VPN**） |
| `DSH_GATE_PORT` | `8080` | 监听端口 |
| `DSH_GATE_UPSTREAM` | `http://127.0.0.1:3080` | 上游 harness 地址 |
| `DSH_GATE_USER` / `DSH_GATE_PASS` | — | 仅本次运行覆盖凭据；若此时还没有配置文件，则用它初始化（写入的仍是哈希） |
| `DSH_GATE_INIT_FROM_STDIN` | — | 设为 `1` 时允许用管道传入三行（用户名、密码、确认密码）完成初始化，供自动化使用 |

示例：

```powershell
$env:DSH_GATE_PORT='8080'; node dsh-login-gate.cjs
```

---

## 安全模型

### 1. 注册入口用一次性 token 保护

启动时生成一次性 token 并打印。**每一次注册请求（GET 表单与 POST 提交）都必须携带该 token**：

- 本机浏览器访问 `/` 或 `/__gate/setup` 会自动 302 到带 token 的地址，所以日常使用**不需要**手工复制链接；
- **直接 POST 而没有 token → 403**；
- 注册成功后入口永久关闭，旧 token 立即失效（重放会得到 401，配置不会被覆盖）。

为什么本机也要 token？**因为「来自 127.0.0.1」不能作为身份证明** —— 你浏览器里任意一个恶意网页都能自动向 `http://127.0.0.1:8080/__gate/setup` 提交表单，该请求同样来自回环地址。攻击者的网页无法读取那个 302 跳转目标，因此拿不到 token。注册页另带 `Referrer-Policy: no-referrer`，避免 token 随 Referer 外泄。

### 2. 凭据以加盐哈希保存

`dsh-login-gate.config.json`（与脚本同目录，首次注册成功时生成）：

```json
{
  "version": 2,
  "user": "dsh",
  "kdf": { "name": "scrypt", "N": 16384, "r": 8, "p": 1, "keylen": 64 },
  "salt": "……（每次写入均为新的 16 字节随机盐）",
  "hash": "……",
  "updatedAt": "2026-09-18T03:22:07.685Z"
}
```

- **没有任何明文字段**；同一个密码两次初始化会得到不同的 `salt`/`hash`。
- 校验使用 `crypto.scrypt` + `timingSafeEqual`（常量时间比较）。
- 空密码、缺失或过短的 `salt`/`hash` **一律判否**。

配置文件状态与启动行为：

| 状态 | 行为 |
| --- | --- |
| 不存在 | 进入网页注册模式 |
| 正常（含 `salt` + `hash`） | 直接服务 |
| 旧版 v1（存在明文 `pass` 字段） | **自动迁移**为加盐哈希，并提示可用 `--init` 更换 |
| JSON 损坏 / 缺少可用哈希 | 备份为 `<配置名>.broken-<时间戳>`，然后进入网页注册模式 |
| v1 但 `pass` 为空字符串 | 视为不可用 → 备份并重新注册（空密码不被接受） |

### 3. 会话用 Cookie，而不是纯 Basic

登录成功后下发 `dsh_gate=<随机 32 字节>` 的 **HttpOnly + SameSite=Lax** Cookie（有效期 12 小时）。

原因是**浏览器的 WebSocket 握手无法携带 `Authorization` 头** —— 若只做 Basic 挑战，GUI 的 RPC 长连接会被门禁一并掐死。Cookie 由浏览器自动携带，WebSocket 才能正常过闸。

同时仍接受 HTTP Basic（`curl -u user:pass`），并在 Basic 通过时顺带下发会话 Cookie，方便脚本使用。

### 4. 请求头改写（让 harness 的 `/api` 信任栅栏放行）

harness 对 `/api` 有 browser-trust 栅栏：`Origin`/`Host` 的 authority 不可信时返回 **403**。由于浏览器访问的是 `:8080`，门禁在转发时改写为上游身份：

| 请求头 | 改写为 |
| --- | --- |
| `Host` | `127.0.0.1:3080` |
| `Origin` | `http://127.0.0.1:3080` |
| `Referer` | 前缀替换为上游 origin |
| `X-Forwarded-Host` / `X-Forwarded-Proto` | 追加客户端侧信息 |

WebSocket 升级请求（`Upgrade`）走同样的改写，并保留路径与查询串。

---

## 内部端点

| 路径 | 方法 | 认证 | 说明 |
| --- | --- | --- | --- |
| `/__gate/setup` | GET | 一次性 token | 注册表单；注册成功后不再可用 |
| `/__gate/setup` | POST | 一次性 token | 提交注册（`user` / `pass` / `confirm` / `token`） |
| `/__gate/login` | POST | — | 登录表单提交（`user` / `pass` / `next`） |
| `/__gate/logout` | GET | — | 清除会话 Cookie 并跳回 `/` |
| `/__gate/health` | GET | **无** | `{"ok":true,"upstream":"…","sessions":N,"setup":false}`，可用于探活 |

其余所有路径（含 `/api`、WebSocket 升级）都需要通过认证才会转发到 harness。

---

## 故障排查

| 现象 | 原因与处理 |
| --- | --- |
| 登录后页面显示 `dsh web authentication required; reopen the URL printed by dsh web.` | 这是 **harness 自身**的第二道令牌门禁。请在 harness 控制台/`dsh web` 打印的**同一个 host** 上打开一次带令牌的 URL（浏览器会以 Cookie 记住，Cookie 不区分端口），之后经 `:8080` 访问即可 |
| `403 Forbidden` 且来自 harness `/api` | 信任栅栏拒绝。确认没有在门禁前面再套一层会改写 `Host`/`Origin` 的代理 |
| `502 Bad Gateway - upstream … is not reachable` | harness 未运行，或 `DSH_GATE_UPSTREAM` 配错 |
| 启动报 `EADDRINUSE` | 端口被占用，用 `DSH_GATE_PORT` 换端口 |
| 忘记密码 | 删除 `dsh-login-gate.config.json` 后重启（回到网页注册），或在运行中用 `--setup` 重新注册。注意：哈希不可逆，无法找回原密码 |
| 丢失注册链接/token | 在**尚未注册**的状态下重启门禁即可打印新的（token 只在内存中，重启即换） |
| `--init` 报「需要交互式终端」 | 后台/服务方式启动没有 TTY。改用默认的网页注册，或设置 `DSH_GATE_USER`/`DSH_GATE_PASS`，或用 `DSH_GATE_INIT_FROM_STDIN=1` 管道传入 |
| 改完密码不生效 | `--init`/`--setup` 只写配置，需要**重启门禁**才会加载新凭据 |

---

## 已验证行为

以下均为实测结果（curl + 原始 socket）：

| 场景 | 结果 |
| --- | --- |
| 未登录 · 脚本客户端 | `401` + `WWW-Authenticate: Basic` |
| 未登录 · 浏览器导航 | `200` HTML 登录页 |
| 密码错误 / 空密码 / 未注册用户 | `401` |
| 正确凭据 · 表单 / Basic | `302` 或放行（并下发会话 Cookie） |
| 认证后 `GET /`、`/api/`、`POST /api/` | 到达 harness（返回 harness 自身响应，**不是 403**） |
| 无会话 WebSocket 升级 | `401`，连接被拒绝 |
| 有会话 WebSocket 升级 | `101 Switching Protocols` + 正确的 `Sec-WebSocket-Accept`，路径/查询串保留，`Host`/`Origin` 已改写 |
| 注册：错误 token | `403` |
| 注册：密码过短 / 两次不一致 | `400`，不写入配置 |
| 注册成功后重放旧 token | `401`，配置未被覆盖 |
| 同一密码两次初始化 | `salt` 与 `hash` 均不同，且新哈希仍能验证原密码 |
| 非 TTY + `--init` 且无环境变量 | 明确报错 + 退出码 `1`，**不会**静默生成密码 |

---

## 安全须知与已知限制

1. **默认只绑 `127.0.0.1`。** 对外提供服务需 `DSH_GATE_HOST=0.0.0.0`，此时**必须**套 HTTPS 或走 VPN/隧道，否则登录表单与 Basic 凭据明文过网（脚本检测到非回环地址时会主动警告）。
2. **harness 仍监听 `127.0.0.1:3080`。** 本机上的任何进程/用户都能绕过门禁直连。本门禁挡的是网络入口，不是本机。
3. **单一账号，无登录限速/锁定。** scrypt 让每次尝试都有成本，但没有失败次数限制；暴露到公网前请自行加限速或改用 VPN。
4. **不提供 TLS**：证书与 HTTPS 终止请交给前面的 nginx/Caddy 等。
5. **会话在内存中**，门禁重启 = 所有会话失效、需要重新登录。
6. **Windows 上 `mode: 0o600` 不构成 ACL 保护**，配置文件的保护依赖「只存哈希、不含明文」。
7. **不是 harness 的替代品**：harness 自带的令牌门禁依然生效，两者是叠加关系。

---

## 文件

| 文件 | 说明 |
| --- | --- |
| `dsh-login-gate.cjs` | 门禁本体（单文件、零依赖） |
| `dsh-login-gate.config.json` | 凭据记录（盐 + scrypt 哈希），首次注册成功时生成 |
| `basic-auth-route-demo.js` | 相关但独立：早前验证「Cordis 动态插件能否做 HTTP Basic 认证」的示例代码。结论是动态插件只能保护自己注册的路由，无法拦截整个 GUI，故改用本门禁方案 |

##我真的很推荐deepseek harness直接将登录模式直接封装进内部，并且最好做端口分离，防止危险调用的情况发生。
