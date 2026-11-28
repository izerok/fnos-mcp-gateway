# MCP 工具面（30 个：16 读 + 14 写）

工具数量与分组以 `src/fnos_mcp/tools/registry.py` 的 `TOOLS` 为准，面板
「能力」页（`/capabilities`）和 `/api/capabilities.json` 都从它直接生成，
不会和 MCP 实际暴露的工具漂移。读写判据：参数里带 `confirm` 的就是写工具。

## 会话与状态（5）

| 工具 | 作用 | 登录判定 |
|---|---|---|
| `fnos_profiles` | 列出当前 token 允许的 profile | — |
| `fnos_login_start` | 生成授权链接（两步登录第一步） | admin 或 `manage_login` |
| `fnos_login_finish` | 提交一次性 code | 先查 token_persisted，再 user info 验证 |
| `fnos_logout` | 清理本机 session（不撤销 NAS 端授权） | admin 或 `manage_login` |
| `fnos_status` | 连接/登录状态概览 | 来自 panel-state 合并徽章 |

## 系统与存储（4）

| 工具 | 作用 | 备注 |
|---|---|---|
| `fnos_system_info` | 机器类型、版本、硬件 | **不用于判断登录** |
| `fnos_storage_overview` | 存储总览 | — |
| `fnos_storage_pools` | 存储池 | — |
| `fnos_storage_disks` | 磁盘 | — |

## 文件（4）

| 工具 | 作用 | 备注 |
|---|---|---|
| `fnos_file_ls` | 列目录 | `path` 须绝对路径，不含 `..` |
| `fnos_file_mkdir` | 目标机上建目录（写） | 同上 |
| `fnos_file_upload` | 网关本地文件 → 目标机目录（写） | `local_file` 必须在网关 `/data/uploads/` 内（见下）；`overwrite: skip/replace/rename` |
| `fnos_file_chown` | 改属主 uid（写） | `recursive: true` 等价 `--sub` |

### 上传目录边界（0.3.1 起）

`fnos_file_upload.local_file` 只能是 `/data/uploads/` 里的普通文件
（写相对名或该目录内的绝对路径都行），拒绝 `..`、符号链接、目录外的
绝对路径与不存在的文件。原因：网关容器里的 `/data/tokens.json`、
`/data/panel-auth.json`、`/data/fnos-cli/`（NAS 登录态）都是秘密，若允许
任意本地路径，持有写权限的 key 就能把它们整文件传到 NAS 上再读走。

要上传自定义文件：先把文件放进 `/data/uploads/`（宿主
`docker cp <file> <容器名>:/data/uploads/`，属主 10001），再调工具。
纯文本 YAML 也可以直接用 `fnos_docker_compose_create` 的 `content`。

## Docker 容器（4）

| 工具 | 作用 | 备注 |
|---|---|---|
| `fnos_docker_ps` | 容器列表 | `docker container ls`，返回 `{"containers": [...]}` |
| `fnos_docker_container_create` | 建容器（写） | `cmd` 每项不能含空格（fnos-cli 切分）；复杂命令走 `fnos_docker_request` |
| `fnos_docker_container_remove` | 删容器（写） | `force` 强制 |
| `fnos_docker_request` | 任意 `appcgi.dockermgr.*` 兜底端点（写） | endpoint 只写名字；body 不能含 `req`/`reqid` |

## Docker Compose（12：4 读 + 8 写）

第一类 compose 工具，端点与语义见 [compose.md](compose.md)。

| 工具 | 作用 | 端点 |
|---|---|---|
| `fnos_docker_compose_list` | 列出 compose 项目及状态 | `composeList` |
| `fnos_docker_compose_containers` | 某个项目下的容器 | `composeContainers` |
| `fnos_docker_compose_logs` | 某个项目的日志 | `composeLog` |
| `fnos_docker_compose_existing_file` | 目录里已有的 compose 文件 | `composeExistingFile` |
| `fnos_docker_compose_create` | 创建项目（可带 `content` 直接写 YAML）（写） | `composeCreate` |
| `fnos_docker_compose_build` | 构建并拉起（= `compose up -d`）（写） | `composeBuild` |
| `fnos_docker_compose_start` | 启动（写） | `composeStart` |
| `fnos_docker_compose_stop` | 停止（写） | `composeStop` |
| `fnos_docker_compose_restart` | 重启（写） | `composeRestart` |
| `fnos_docker_compose_clear` | 清理容器但保留项目记录（≈ `down`）（写） | `composeClear` |
| `fnos_docker_compose_delete` | 删除项目登记（写） | `composeDelete` |
| `fnos_docker_compose_cancel` | 取消进行中的构建（写） | `composeCancel` |

## 监控（1）

| 工具 | 作用 | 登录判定 |
|---|---|---|
| `fnos_monitor_cpu` | CPU | 需要 session，可作认证探测 |

## 写工具门禁（14 个，默认关闭）

全部满足以下门槛才会执行，任一不满足即拒绝并审计：

1. token 是 **admin**，或具备 `manage_deploy` 能力；
2. 目标 profile 在 profiles.json 里 **`allow_dangerous: true`**；
3. 同一请求里 **`confirm: true`**；
4. 每次调用写审计（params 的 confirm 剥离后 SHA-256 放 `sub_reason`，不记原文）。

被拒绝的写请求同样入审计（0.3.1 起）：事件 `deploy_denied`，`result` 为
`forbidden` / `not_allowed` / `confirm_missing` / `rate_limited`（0.3.2 起），带 `token_id`、`profile`
与 `client_ip`，不含参数值。

## 限速

- 面板动作按 FR-35 限速（登录、探测、写配置、密钥操作等）。
- 面板动作按 FR-35 限速（登录、探测、写配置、密钥操作等）。
- `/mcp` 按 **token** 限速，但 **默认关闭**（本地网关一般不需要节流）：
  在面板「设置」里填 `120/60`（或设 `FNOS_RATE_LIMIT_MCP_CALL`）后，每把
  key 每 60 秒最多 120 次，超限返回 429 + `Retry-After`，不会进入
  FastMCP；换一把 key 不受影响。面板侧限速仍在 `/api/*` 独立生效。
- 写工具另有更紧的内闸：`mcp_write` 20 次/60 秒，按 token 计，只在权限
  与 `confirm` 两道门都通过后才扣次数；超限报 `rate_limited`，同样记
  `deploy_denied` 审计。
- 每一项限速都可以在面板「设置」里改（即时生效），或用
  `FNOS_RATE_LIMIT_<KIND>` 启动期覆盖；面板保存值优先。完整表格见
  [configuration.md](configuration.md)。

`fnos_docker_request` 仍然保留，但只是兜底口——常用的 compose 生命周期
已经有第一类工具，不需要再拼 `endpoint`/`body`。

## 调用规则

- profile 只接受注册表里的名字；`host` / `port` / `scheme` 参数一律拒绝。
- `X-FNOS-Profile` 请求头是固定值（pin）：设置后工具参数必须省略或与
  header 相同，否则拒绝；不设置时用工具参数或 `default_profile`。
- `login` / `logout` 只允许 admin 或具备 `manage_login` 能力的 token。
- `system info` 不要求 session，未登录也可能成功——永远不用它判断登录。
- 在面板「能力」页可以下载 `/api/capabilities.json`，里面是同一份目录的
  机器可读版本（名字、分组、读写、必填参数、端点、门禁）。
