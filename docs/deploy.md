# 部署（M2 + 面板机器管理 + 访问密钥）

只放内网 / VPN / Tailscale。面板与 MCP 都是管理员入口，P0 不做公网。

## 准备文件

```bash
cp config/profiles.example.json config/profiles.json   # 首次启动的 seed，填真实地址
cp config/tokens.example.json config/tokens.json       # Agent 密钥 seed；token 只填 sha256
head -c 32 /dev/urandom > config/panel-session.key && chmod 600 config/panel-session.key
```

token 的 sha256 算法：`printf '%s' '<token>' | sha256sum`。面板本身不再用
token 登录：首次访问时设置管理员密码；`tokens.json` 里的是给 Agent 用的
MCP 密钥（也可以在面板“访问密钥”里新建，不必预置）。

`profiles.json` 挂载为只读 seed。容器首次启动时把它复制到
`FNOS_PROFILES_STORE`（通常是 `/data/profiles.json`，0600）；之后面板
新增/编辑/删除机器只改这个可写副本，不再回写 seed。

`tokens.json` 同理：首次启动复制到 `FNOS_TOKENS_STORE`
（通常是 `/data/tokens.json`，0600），之后面板只改可写副本。

## 启动

```bash
docker compose up -d --build
curl http://127.0.0.1:8000/healthz
```

第一次打开 `http://<部署机>:8000` 会进入“设置管理员密码”。密码至少 8 位，
服务端只保存加盐 scrypt 哈希（`/data/panel-auth.json`，0600）。忘记密码：
删除该文件后重启，下一次访问重新设置；已签发的面板会话同时失效。

Caddy 反代示例（TLS 由 Caddy 负责，容器只监听反代网络）：

```caddyfile
mcp.example.com {
    reverse_proxy 127.0.0.1:8000
}
```

`/healthz` 不要经公网反代暴露；如必须暴露，用 matcher 限制来源网段。

## 面板新增/编辑/删除机器

入口在“机器”区块右上角的“添加机器”，以及每行的“编辑”“删除”。

- 机器写操作只对已用密码登录的管理员开放；Agent 的 MCP 密钥不能登录
  面板。
- 表单字段：机器名、地址、端口、HTTPS/HTTP、`allow_insecure_http`、
  `tls_insecure`、备注。机器名保存后不可修改，避免丢失已有 session。
- 不保存 NAS 账号或密码；登录仍走 OAuth 两步式。
- 写入使用临时文件 + fsync + `os.replace`，文件 0600；进程内锁避免
  并发读改写互相覆盖。服务必须单 worker / 单副本。
- 编辑会保留面板不展示的高级字段（如 `authorization_hosts`、
  `allow_dangerous`）；清除复选框会移除对应的不安全选项。
- 删除会同时丢弃该机器的面板状态并释放未完成的登录租约；NAS 本身不受
  影响，之后可以重新添加。
- `default_profile` 为空或指向不存在的机器时，新建第一台机器会成为
  默认 profile。
- 要恢复 seed：停止容器，删除 `/data/profiles.json`（或整个数据卷），
  再启动；已有 `panel-state` / CLI session 不会被自动清理。
- 地址由容器发起访问。只填写你拥有或被授权管理的 NAS；不要把它当作
  任意 URL 代理，也不要让不可信用户获得面板密码。

## 访问密钥（Agent ACL）

“访问密钥”区块给每个 Agent 发一把 MCP key：

- **名称**：面板内唯一，用于区分 Agent。
- **角色**：`operator` 只读与测试；`admin` 额外允许登录 / 本机退出。
- **机器 ACL**：勾选具体机器，或“全部机器”（包含以后新增的）。ACL
  之外的 profile 在 MCP 里返回 `profile.not_found`，与不存在的机器
  不可区分。
- **附加能力**：`manage_login` 给 operator 开放登录/退出；
  `manage_profiles` 仅为旧配置兼容保留（面板本身只有管理员）。
- **明文加密保存，可再次复制**：新建或轮换后，明文用面板会话密钥派生的
  AES-256-GCM 加密写入 `/data/tokens.json`（0600），MCP 校验仍用 sha256。
  登录面板后可在列表里“复制密钥”或“复制 JSON”（含真实 key 与
  `MCP_PUBLIC_URL`）。从旧版 `tokens.json` 复制来的 seed key 没有密文，
  列表标记“早期密钥”，轮换后可复制。
- **复制**：列表与一次性弹窗共用同一套复制逻辑；HTTP 局域网下 Clipboard
  API 不可用时自动回退到 `execCommand`，仍失败则展开/选中文本供手动复制。
  关闭弹窗会清空明文 DOM。读取明文会写审计 `token_secret_read`（只记
  `key_id`），响应 `Cache-Control: no-store`。
- **会话密钥影响**：更换 `PANEL_SESSION_SECRET_FILE` 后，已有密文无法解密，
  列表无法复制（显示“早期密钥”）；这些 key 仍可用于 MCP，轮换一次即可恢复
  可复制状态。
- keys 上限 50 把，每把最多 32 台机器 ACL。
- 要恢复密钥 seed：删除 `/data/tokens.json` 后重启（会重新从挂载的
  `tokens.json` 复制；面板里建过的 key 会丢失）。

## 审计留存与轮转

审计写入 `/data/audit.jsonl`（append-only JSONL，0600，字段白名单）。
当前文件超过 50MB 时轮转为 `audit.jsonl.1`，旧的 `.1` 顺延为 `.2`……
最多保留 6 份归档（连同当前文件共 7 个），更旧的归档在下一次轮转时
删除，目录占用有上限。审计不含 token、密码、完整 sha256、code、授权
URL、地址等敏感值；密钥事件只记 `key_id`。面板没有修改审计的入口。
需要长期保存时，请在宿主机上从数据卷定期备份归档文件。

## 环境变量

| 变量 | 说明 |
|---|---|
| `FNOS_PROFILES_PATH` | profiles.json seed 位置（默认 /etc/fnos-mcp/profiles.json，只读挂载） |
| `FNOS_PROFILES_STORE` | 面板可写 profile store（建议 /data/profiles.json）；未设置时直接写 `FNOS_PROFILES_PATH`，通常因只读挂载而失败 |
| `FNOS_TOKENS_PATH` | tokens.json seed 位置（默认 /run/secrets/mcp_tokens.json，只读挂载） |
| `FNOS_TOKENS_STORE` | 面板管理的访问密钥 store（建议 /data/tokens.json）；首次启动从 seed 复制，未设置时直接读写 `FNOS_TOKENS_PATH` |
| `FNOS_DATA_DIR` | 持久卷（默认 /data，含 fnos-cli、home、panel-state.json、panel-auth.json、profiles.json、tokens.json、locks/） |
| `PANEL_SESSION_SECRET_FILE` | 面板会话签名密钥（默认 /run/secrets/panel_session_secret 或 /data/panel-session.key）；缺失或短于 32 字节启动失败 |
| `SSL_CERT_FILE` | 可选：私有 CA bundle 路径；不设置则使用系统 CA 校验 |
| `MCP_PUBLIC_URL` | 对外展示的 MCP endpoint（默认取请求根地址 + /mcp） |
| `TRUSTED_PROXY_CIDRS` | 信任的反代网段（默认不信任任何代理头） |
| `PANEL_ALLOWED_ORIGINS` | 多域名反代时的精确 origin allowlist |
| `FNOS_CLI_BIN` | CLI 二进制位置（默认 fnos-cli；测试时指向假 CLI） |
| `FNOS_CLI_CONFIG_DIR` | CLI session 目录（默认 /data/fnos-cli，按 profile 隔离） |
| `FNOS_SKIP_CLI_CHECK` | `=1` 跳过启动时的 CLI 版本自检（仅调试；默认会自检并拒绝不兼容版本） |
| `MCP_PORT` | 容器内监听端口（镜像内默认 8000） |
| `FNOS_RATE_LIMIT_<KIND>` | 启动期覆盖单项限速：`N/WINDOW`，或 `off` 关闭。`KIND` 取 `MCP_CALL`、`PANEL_LOGIN`、`PROBE`、`TEST`、`LOGIN_START`、`LOGIN_FINISH`、`PROFILE_WRITE`、`TOKEN_WRITE`、`TOKEN_SECRET`；**`MCP_CALL` 默认关闭**；写错格式启动失败。**面板「设置」保存的值优先生效**（`/data/settings.json`）。详见 [configuration.md](configuration.md) |

## 从旧版本升级（面板 token 登录 → 密码登录）

- 面板不再接受 `tokens.json` 里的 token 登录。升级后第一次访问
  `/login` 会要求设置管理员密码；数据卷里已有 `/data/tokens.json`
  时不会重建，原有 MCP key 继续有效。
- `/data/tokens.json` 不存在时会从挂载的 seed 复制一次；此后以面板
  为准。若旧部署只有 `tokens.json` 而从未设置 `FNOS_TOKENS_STORE`，
  升级首次启动会创建 `/data/tokens.json`，原有 MCP key 不变。
- `admin-token.txt` 之类用于面板登录的旧凭据到此失效；如它同时是一把
  MCP key，仍可按密钥使用，但建议在面板里轮换后删除该文件。
