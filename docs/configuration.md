# 可配置项总览

本页列出网关所有可以由运维手动调整的开关，以及目前写死在代码里的常量。
三条配置路径：

1. **面板「设置」（即时生效）**——限速、探测、面板会话、审计轮转、CLI
   超时，保存在 `/data/settings.json`，改完不用重启；
2. **环境变量**（改完需重建容器）——路径、地址、代理信任等启动期配置；
3. **面板机器/密钥管理**——机器与密钥的常规编辑，即时生效。

## 面板「设置」（0.3.3 起，即时生效）

登录面板 → 右上「设置」弹窗。全部留空 = 保持现值；保存后立即生效并记
审计 `settings_updated`。限速格式 `次数/窗口秒数`（如 `120/60`）或
`off`（不限速）；写错格式不会保存。

| 项 | 默认 | 范围 |
|---|---|---|
| MCP 调用限速（每把 key） | **off** | 1–10000 次 / 1–3600 秒 |
| MCP 写操作限速（每把 key） | 20/60 | 同上 |
| 面板登录限速（每 IP） | 10/300 | 同上 |
| 测试网络 / 测试连接 / 发起登录 / 提交授权码（每机器） | 30/60、10/60、5/60、10/300 | 同上 |
| 保存机器 / 密钥管理 / 读取密钥明文（每会话） | 20/60、10/60、30/60 | 同上 |
| 探测超时 | 5 秒 | 1–30 |
| 探测并发 | 4 | 1–16 |
| 全部探测等待 | 10 秒 | 5–120 |
| 面板会话时长 | 12 小时 | 1–168 |
| 审计单文件上限 / 保留份数 | 50 MB / 7 | 1–1024 / 2–50 |
| CLI 读取 / 日志 / 动作 / 构建超时 | 60 / 120 / 180 / 600 秒 | 10–900 / 30–1800 |

设置文件损坏或字段越界时按默认值运行，不会导致启动失败；上限收紧
（如会话时长最低 1 小时）是刻意的，防止手滑把自己锁在外面。

## 环境变量

| 变量 | 默认值 | 作用 |
|---|---|---|
| `MCP_PORT` | `8000` | 监听端口 |
| `FNOS_DATA_DIR` | `/data` | 可写数据目录（profiles、tokens、session、审计、锁） |
| `FNOS_PROFILES_PATH` | `/etc/fnos-mcp/profiles.json` | 机器配置 seed（只读） |
| `FNOS_PROFILES_STORE` | 未设置 | 设置后 seed 首次复制到这里，之后以副本为准（面板改它） |
| `FNOS_TOKENS_PATH` | `/run/secrets/mcp_tokens.json` | Agent 密钥 seed（只读） |
| `FNOS_TOKENS_STORE` | 未设置 | 设置后 seed 复制到可写副本，面板管理副本 |
| `FNOS_CLI_BIN` | `fnos-cli` | CLI 可执行文件 |
| `FNOS_CLI_CONFIG_DIR` | `<data>/fnos-cli` | CLI session 目录（按 profile 隔离） |
| `FNOS_SKIP_CLI_CHECK` | 未设置 | `=1` 跳过启动时的 CLI 版本自检（仅调试） |
| `PANEL_SESSION_SECRET_FILE` | 无，回退 `/data/panel-session.key` | 面板会话签名密钥文件（≥32 字节） |
| `MCP_PUBLIC_URL` | 无 | 面板“接入”卡展示的 MCP 地址 |
| `TRUSTED_PROXY_CIDRS` | 空 | 只有来自这些网段的请求才信任 `X-Forwarded-For` |
| `PANEL_ALLOWED_ORIGINS` | 空 | 额外允许的 Origin（反代域名） |
| `SSL_CERT_FILE` / `SSL_CERT_DIR` | 无 | 额外 CA；同时传给 CLI（自签 NAS 用） |
| `TRIM_CLI_DISTRIBUTION` | 镜像固定 `fnos` | fnos-cli 运行模式 |
| `FNOS_CLI_SESSION_STORAGE` | 镜像固定 `file` | CLI session 持久化方式 |

## 限速（`FNOS_RATE_LIMIT_<KIND>`）

启动期覆盖；面板「设置」保存的值优先生效（settings.json 优先于环境变量）。
`N/WINDOW` 表示每 WINDOW 秒最多 N 次；`off`（或 `0/60`、`none`）表示不限速。
取值写错会在启动时报错，不会静默关掉保护。MCP 默认**不限速**。

| 变量（后缀） | 默认 | 限速键 | 说明 |
|---|---|---|---|
| `MCP_CALL` | **off** | 每个 token | 所有 `/mcp` 请求 |
| `MCP_WRITE` | 20/60 | 每个 token | 写工具内闸（权限与 confirm 通过后才扣次数） |
| `PANEL_LOGIN` | 10/300 | 客户端 IP | 面板登录 |
| `PROBE` | 30/60 | token + 机器 | 测试网络/连接 |
| `TEST` | 10/60 | token + 机器 | 测试连接 |
| `LOGIN_START` | 5/60 | token + 机器 | 发起 NAS 登录 |
| `LOGIN_FINISH` | 10/300 | token + 机器 | 提交 code |
| `PROFILE_WRITE` | 20/60 | token | 面板改机器 |
| `TOKEN_WRITE` | 10/60 | 面板会话 | 密钥增删改轮换 |
| `TOKEN_SECRET` | 30/60 | 面板会话 | 复制明文密钥 |

例：把 MCP 限到每分钟 120 次，同时关掉面板登录限速：

```yaml
environment:
  FNOS_RATE_LIMIT_MCP_CALL: "120/60"
  FNOS_RATE_LIMIT_PANEL_LOGIN: "off"
```

## 机器配置（profiles.json / 面板“机器”→“编辑”）

| 字段 | 默认 | 作用 |
|---|---|---|
| `default_profile` | 无 | 工具不传 `profile` 时使用 |
| `name` | — | 只接受 `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`，面板里只读 |
| `host` / `port` / `scheme` | — | 仅存服务端；MCP 客户端永远不能传 |
| `allow_insecure_http` | `false` | 允许 http（否则只接受 https） |
| `tls_insecure` | `false` | 跳过证书校验（自签机器；面板显示“跳过 TLS 校验”） |
| `allow_dangerous` | `false` | 该机器是否允许部署写工具 |
| `description` | `""` | 备注 |
| `authorization_hosts` | `[]` | 额外允许的授权链接 host（默认只允许本机 origin） |

## 密钥与权限（面板“访问密钥”）

- `role`：`admin` / `operator`
- `capabilities`：`manage_login`、`manage_deploy`
- `profiles`：机器名列表或 `["*"]`（ACL）
- 明文密钥只在创建/轮换时显示一次；`/data/tokens.json` 里是 sha256 +
  AES-GCM 密文（面板会话密钥派生）。
- 面板管理员密码：首次访问设置，≥8 字符、≤128 字符，scrypt 存储；忘记
  密码删除 `/data/panel-auth.json` 后重启重设。

## 目前写死、尚不能配置

限速、探测、会话、审计轮转、CLI 超时已可在面板「设置」调整（见上），
以下是剩余的代码常量：

| 常量 | 值 | 位置 |
|---|---|---|
| 探测响应体上限 | 64 KB | `probe.py:19` |
| 认证结果新鲜期 | 24 小时 | `state_store.py:26` |
| 锁 TTL | 探测 5 秒 / 会话 300 秒 | `locks.py:26-27` |
| 密钥数量 / ACL 长度 / 名称 | 50 / 32 / 64 | `token_store.py:41-43` |
| 面板密码长度 | 8–128 | `panel_auth.py:33-34` |
| scrypt 参数 | N=16384, r=8, p=1 | `panel_auth.py:28-30` |
| compose `content` 上限 | 256 KB | `tools/registry.py` |
| 写审计摘要 | SHA-256（confirm 剥离） | `tools/registry.py` |

如果这些里有你想调的（例如探测响应体上限、认证新鲜期），告诉我
哪个，我按同样的方式接出来。
