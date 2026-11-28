# CLI 升级手册（PLAN §4.5）

fnos-cli 是会变的外人。升级时只按本手册走，不凭感觉、不只改版本号。

## 钉死的位置（只有这三处能改版本）

1. `Dockerfile` 的 `ARG FNOS_CLI_VERSION` 与两架构 `.gz` SHA-256。
2. `src/fnos_mcp/cli_adapter.py` 的 `SUPPORTED_CLI_VERSIONS` / `CLI_VERSION`。
3. 本文件的“已验证版本”记录（升级后更新）。

已验证版本：**0.6.2**（2026-11-24 升级）。
0.5.1 记录（历史）：Skill zip SHA-256 `318038b6e50599297dc83dc23550cc405a31dd3c062c7037c90b98383170cb2a`；
Linux x64 `.gz` `71bbf3947905c452f467841e200aa0994e04d0fa4470dfdc39fb79bf12cc74a6`；
Linux arm64 `.gz` `58db3d9f23f884a103b89af3b81de5b35aa520570df725f515e7b2e3d53b720d`。
0.6.2 哈希（来源：直下两个资产逐个计算；tag 内没有 release.json
也没有 SHA256SUMS，2026-11-25 经 GitHub API 核对资产清单确认）：
Linux x64 `.gz` `f3233408662bf667355135771ce0d6db856ef334f16c5a552a53970976ffdc79`；
Linux arm64 `.gz` `db7d7a1ecac51bf1213b1b3a7eee77e14b5d16604ace00f83ba6587dad649ebc`。
**tag 内没有 release.json，也没有 SHA256SUMS**（v0.5.1 与 v0.6.2 均为
12 个资产）；升级时只能直下新版两个 Linux 资产、逐个计算 SHA-256 后更新钉值。

### 0.5.1 → 0.6.2 差异结论（2026-11-24 实测）

- 两版二进制 `--help` 树（318 条命令路径，含 `docker container create`
  级别）完全一致；唯一新增是 `login` 的 `--device-name` / `--agent-name`。
- npm tarball、skill zip 文件树相同，变化仅为文档/manifest/provenance。
- 部署所用子命令（`file upload/mkdir/chown`、`docker container create/rm`、
  `docker request`）无任何变化。
- 登录：升级后旧 session 不迁移（两台 NAS 都要重新授权）；新登录可带
  `--agent-name fnos-mcp`，NAS 授权管理里显示为 `<主机名>-fnos-mcp`。
  适配层暂未传该参数（login_start 拼写不变）；要启用时只改 login_start。

## 待办：下一次升级（无）

0.6.2 已于 2026-11-24 完成升级与全量回归。下一次官方发版时按上面步骤走：
只改三处钉死位置 → 能力探测出差异表 → 只改适配层 + fake 夹具 + 本文件 →
全回归 → 真机重走登录/状态验收（升级后旧 session 不迁移，须重新授权）。

## 升级步骤

1. **发现**：只盯官方 Release（`fnnas-labs/fnos-cli-skill`），不盯 main
   分支文档（main 曾出现 0.5.1 包内没有的 `--agent-name` 参数）。
2. **钉死**：在分支里改上面三处；其余文件不动。
3. **探测**：跑能力探测——`python -m fnos_mcp.cli_capabilities` 思路：
   用 `CliRunner` 对新二进制跑 `--version` 与 `--help`，输出《能力差异表》
   （新增/删除/改名的命令与参数、登录流程变化、错误信号变化）。
   `tests/test_cli_capabilities.py` 有对应的回归测试。
4. **适配**：差异只改 `cli_adapter.py` + `tests/fake_cli.py` 夹具 + 本文件；
   面板、MCP 工具、状态模型、审计、部署文件不动。若差异大到适配层装不下
   （例如登录流程换代），停下来汇报，另立升级方案，不硬塞。
5. **回归**：假 CLI 单测（新旧两套夹具）→ MCP 冒烟（`POST /mcp` tools/list/call）
   → 面板 API/探测/安全测试 → 容器测试（非 root、只读 rootfs、卷持久化）。
6. **真机**：两台 NAS（或一台 NAS 两个 profile）重走与登录/
   状态相关的用例。**CLI 升级后旧 session 不迁移，必须重新授权**，
   验收前先做一次重新登录。
7. **发布**：发布说明写明 CLI 版本、哈希、是否须重新授权。
8. **回滚**：回滚到上一镜像 tag 即可；`/data` 卷里的旧 session 与新版 CLI
   不互通，回滚后同样须重新授权——写进发布说明。

## 适配层只认的结构化信号

- `token_persisted` / `refresh_token_persisted`（bool）
- `authorization_url`（原样返回，调用方按 FR-21 校验）
- `saved proxy session is required`（user info 无 session 的文档化信号）
- JSON 里的结构化 error code（`session_expired` / `token_expired` /
  `unauthorized` / `permission_denied` / `code_expired`）

人类可读的错误文本一律不作业务判断。读-only 子命令的拼写
（`storage overview/pools/disks`、`file ls`、`docker ps`、`monitor cpu`）
来自 Skill 参考文档，已用真实 `--help` 复核；拼写一变，
`test_cli_adapter` 先失败，而不是用户先发现。
