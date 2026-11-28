# Docker Compose 工具（端点、语义与来源）

本页记录 `fnos_docker_compose_*` 这 12 个工具背后的 fnOS 端点、请求体、
返回形状和语义，以及这些结论是怎么来的。端点全部来自 NAS 上 Docker 应用
自己的前端代码（`/apps/docker/assets/index-*.js`），并在真机上用
`fnos-cli docker request` 逐个读过一遍，不是从 CLI 字符串或文档猜的。

## 端点

全部走 `appcgi.dockermgr.*`，由 `fnos-cli docker request <endpoint> --json <body> --yes`
调用（CLI 认为 generic request 是写操作，读探测也要 `--yes`）。

| 端点 | 请求体 | 返回 |
|---|---|---|
| `composeList` | 无 | 裸数组：`[{Name, Folder, ConfigFiles, Status, Containers:{running,total}, Created}]` |
| `composeContainers` | `{"project_name"}` | 数组（容器对象） |
| `composeLog` | `{"project_name"}` | 字符串数组（注意是单数 `composeLog`） |
| `composeExistingFile` | `{"folder"}` | `{"ConfigFiles": "compose.yaml"}` |
| `composeCreate` | `{"auto_build", "file", "folder", "project_name"}` | 成功响应 |
| `composeBuild` | `{"project_name"}` | 成功响应 |
| `composeStart` / `composeStop` / `composeRestart` | `{"project_name"}` | 成功响应 |
| `composeClear` | `{"project_name"}` | 成功响应 |
| `composeDelete` | `{"project_name"}` | 成功响应 |
| `composeCancel` | `{"project_name"}` | 成功响应 |

## 语义

- **`composeBuild` 就是 `docker compose up -d`**：构建镜像并拉起容器，
  不是单纯 `build`。首次部署 = `composeCreate` + `composeBuild`。
- **`composeClear` ≈ `down`**：删容器/网络，但保留项目登记，之后还能再
  `composeBuild`。**`composeDelete`** 才是把项目从 fnOS 的 compose 列表里
  删掉，不可逆；它会不会顺带删目录里的文件没有在真机上验证过，删之前
  先用 `fnos_file_ls` 看一眼目录。
- **没有** `composeDetail`、`composeUp`、`composeDown`，也**没有**读取或写入
  compose 文件内容的端点。要看文件只能 `composeExistingFile` 判断目录里已有
  什么文件；要写入只能上传文件后 `composeCreate`（或先上传再重建）。
- `composeCancel` 只对正在进行中的 build/up 有意义。

## folder 格式（最容易踩的坑）

- compose 端点收的是**卷内相对路径**，不带前导斜杠：
  `vol1/1000/docker/app`。
- CLI 的 file 上传接口收的是**绝对路径**：`/vol1/1000/docker/app`。
- 本网关的 `fnos_docker_compose_*` 统一收相对或绝对都行，内部会
  `lstrip("/")` 归一化，然后拒绝：控制字符、反斜杠、`..`、以及不在
  `vol<N>/` 下的路径。`compose_create` 带 `content` 时，上传前会自己
  补上 `/` 前缀。
- `project_name` 必须匹配 `^(?![_-])[a-z0-9_-]{1,63}$`（同 Compose 规范，
  不能以 `_`/`-` 开头）。
- `file` 只能是 `*.yml` / `*.yaml` 文件名，不能带路径。

## MCP 工具

| 工具 | 读写 | 端点 |
|---|---|---|
| `fnos_docker_compose_list` | 读 | `composeList` |
| `fnos_docker_compose_containers` | 读 | `composeContainers` |
| `fnos_docker_compose_logs` | 读 | `composeLog` |
| `fnos_docker_compose_existing_file` | 读 | `composeExistingFile` |
| `fnos_docker_compose_create` | 写 | `composeCreate` |
| `fnos_docker_compose_build` | 写 | `composeBuild` |
| `fnos_docker_compose_start` | 写 | `composeStart` |
| `fnos_docker_compose_stop` | 写 | `composeStop` |
| `fnos_docker_compose_restart` | 写 | `composeRestart` |
| `fnos_docker_compose_clear` | 写 | `composeClear` |
| `fnos_docker_compose_delete` | 写 | `composeDelete` |
| `fnos_docker_compose_cancel` | 写 | `composeCancel` |

读工具只需要目标机有有效 session。写工具走统一门禁：admin 或
`manage_deploy` 能力 + profile `allow_dangerous: true` + `confirm: true`，
每次调用写审计（`sub_reason` 是 confirm 剥离后参数的 SHA-256）。

## `fnos_docker_compose_create` 的 content 便捷参数

除了“用户自己先把 YAML 传到目标机”之外，`create` 支持直接带 `content`
（YAML 文本，≤256KB，不允许 NUL）：

1. 网关在 `/data/uploads/` 下建一次性子目录（0700），把内容写成
   **`file` 参数指定的文件名**（0600）。文件名必须与 `composeCreate`
   引用的 `file` 完全一致——2026-11-26 真机确认 CLI 的 `file upload`
   保留**本地 basename**，早先的随机名写法会让远端文件与项目登记对不上；
2. 用 CLI 的 file upload 传到目标机 `folder`，覆盖同名文件；
3. 调 `composeCreate`；
4. 无论成功失败，本地临时文件与子目录立即删除（测试覆盖，argv 断言上传名
   与 `composeCreate.file` 一致）。

这样 Agent 一次调用就能建项目，不必先 `fnos_file_upload`。要改已有项目的
compose 文件时，同样先上传（覆盖）再 `composeCreate` / `composeBuild`。

## 超时

`build` / `clear` / `delete` 用 600 秒，其余生命周期 180 秒，
`list` / `containers` 60 秒，`logs` 与 `create` 120/300 秒。
构建大镜像仍可能超过 600 秒，超时会以 `cli.failed` 返回，不会无限挂住。

## 来源核对

- 2026-11-25：从 NAS Docker SPA 的 `index-*.js` 中提取端点名与请求体字段，
  再用 `fnos-cli docker request` 在真机上验证 `composeList`、`composeContainers`、
  `composeLog`、`composeExistingFile`、`composeCreate` 的实际返回形状。
- 同一轮研究（社区/文档交叉）确认 `composeBuild` 承担 up 语义，
  `composeClear` 保留项目记录，且不存在 detail/up/down/文件读写端点。
- 2026-11-26：真机验证 `file upload` 保留本地 basename、`file ls` 返回
  条目数组；`file download-url` 的 URL 被 **CLI 自身**掩码成 `[REDACTED]`
  （二进制内含 `TOKEN/PASSWD/SECRET/API_KEY` 掩码逻辑），所以“在网关里读
  NAS 文件内容”不能靠它，需要另找端点。同一轮还确认 CLI 暴露
  `containerStart/Stop/Restart/Inspect`、`imageList/imagePull/imageRemove`
  等 dockermgr 端点，可做后续迭代。
- 端点常量集中在 `src/fnos_mcp/cli_adapter.py` 的 `COMPOSE_ENDPOINTS` /
  `COMPOSE_ACTIONS`；面板能力页的“端点”一栏也从这里来。
