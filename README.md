# fnos-mcp：fnOS 多机 MCP 网关

一个 Docker 容器、一套 HTTP MCP 服务，管理多台 fnOS NAS。

AI Agent 通过 MCP 工具操作多台 NAS；管理员通过 Web 面板看连通状态、
处理登录、发放带 ACL 的访问密钥。所有对 NAS 的实际操作都由官方
fnos-cli 在容器内部代为执行——Agent 的请求不会被原样转发给 NAS，
Agent 也永远接触不到 NAS 的地址与账号凭据。

## 特性

- **多机管理**：一个网关管理多台 fnOS，机器清单（profiles）在服务端
  配置，调用方只能按机器名引用，不能传入任意地址。
- **Web 面板**：连通汇总、机器列表、四层诊断（网络 / TLS / 认证 /
  配置）、登录与本机退出、连接拓扑、能力清单页；管理员可在面板
  新增 / 编辑 / 删除机器，管理访问密钥。面板首次访问设置管理员
  密码（scrypt 哈希存储）。
- **运行时设置**：限速、探测间隔、会话与审计参数、CLI 超时可在面板
  设置页运行时调整，不必改文件重启。
- **MCP 服务**：Streamable HTTP，共 30 个工具（16 读 + 14 写），
  清单见 `docs/tools.md`。调用限速为读 120 次/分、写 20 次/分（每密钥，
  可在设置页调整）。每个访问密钥带角色、能力与机器 ACL；
  ACL 之外的机器返回与不存在相同的 404，不泄露信息。
- **写操作门禁**：部署类写工具（含 Docker Compose 全生命周期）
  需要同时满足：密钥为 admin 或带 `manage_deploy` 能力、目标机器
  在配置中开启 `allow_dangerous`（默认关闭）、请求带
  `confirm: true`；全程审计，审计只记录参数的 SHA-256 摘要，
  不记录原文。
- **官方登录流程**：登录走 fnOS 官方两步授权（浏览器打开 NAS 的
  授权页确认 + 一次性 code 换取会话），网关不保存 NAS 账号密码，
  只保存 CLI 会话（持久卷 `/data/fnos-cli`）。

## 架构与界限

```
Agent ──HTTP (Streamable HTTP + Bearer 密钥)──▶ MCP 服务
                                                    │ 进程内调用
                                                    ▼
                                               CLI 适配层（唯一碰 CLI 的模块）
                                                    │ 本地子进程
                                                    ▼
                                               官方 fnos-cli（钉版，镜像内）
                                                    │ 按机器配置 HTTP / HTTPS
                                                    ▼
                                                  目标 NAS
```

- 底座是官方 fnos-cli **0.6.2**，版本钉死：构建镜像时下载并校验
  SHA-256、做 `--version` 自检；运行时绝不下载 CLI。
- 唯一允许调用 CLI 的模块是 `src/fnos_mcp/cli_adapter.py`。官方 CLI
  升级时只动适配层、钉版与哈希，面板、MCP 工具与状态模型不变；
  升级步骤见 `docs/cli-upgrade.md`。
- 已知例外：`fnos_docker_request` 是受门禁的兜底工具，可调用
  `appcgi.dockermgr.*` 端点（端点名受正则约束、body 不得自带
  req/reqid）。它同样受上述写门禁约束，但不属于「每操作一个窄
  包装」的常规工具面，使用前请确认目标机器已开启
  `allow_dangerous` 的含义。

## 快速开始（Docker Compose）

```bash
cp config/profiles.example.json config/profiles.json   # 改成你的机器
# 准备两个 secret 文件（见 compose.yaml 的 secrets 段）：
#   config/tokens.json          cp config/tokens.example.json config/tokens.json，之后在面板创建密钥
#   config/panel-session.key    head -c 32 /dev/urandom > config/panel-session.key
docker compose up -d --build
# 打开 http://127.0.0.1:8000/login ，首次访问设置管理员密码
```

也可以直接用已发布镜像（GHCR / Docker Hub 上的
`fnos-mcp-gateway`）：把 compose.yaml 中的 `build: .` 去掉后
`docker compose pull && docker compose up -d`。

容器默认只绑本机回环、单副本单 worker、以 UID 10001 只读根文件
系统运行。对局域网开放时请在前面加反向代理并启用 TLS；本服务的
定位是内网 / VPN 环境，不要直接暴露到公网。部署细节见
`docs/deploy.md`。

## 本地开发

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
cp config/profiles.example.json /tmp/profiles.json
FNOS_PROFILES_PATH=/tmp/profiles.json FNOS_PROFILES_STORE=/tmp/fnos-data/profiles.json \
  FNOS_TOKENS_PATH=/tmp/tokens.json FNOS_DATA_DIR=/tmp/fnos-data \
  FNOS_CLI_BIN=/usr/local/bin/fnos-cli \
  python -m fnos_mcp
```

测试全部使用假 CLI，不联网、不碰真机：

```bash
FNOS_FAKE_STATE_FILE=/tmp/fnos-fake-state.json pytest -q   # 215 个测试
python tests/smoke_m1.py
python tests/smoke_m2.py
```

## 安全模型要点

- 目标地址只来自服务端 profiles，任何调用方参数都不能指定主机、
  端口或协议；网络探测只测配置内的目标，不带凭据、不走 CLI。
- 面板与 MCP 共用同一套密钥 ACL；面板写操作要求管理员会话 +
  CSRF 校验；授权链接只出现在当前登录对话框中并禁止缓存。
- 登录 / 连接测试有 per-profile 会话锁，面板与 MCP 共用，冲突
  返回 409 / `session.locked`。
- 审计日志为追加式 JSONL（字段白名单、0600、超限轮转），不记录
  密钥、授权链接与写操作参数原文。

## 文档

- `docs/deploy.md`：部署、持久化、面板的机器与密钥管理
- `docs/tools.md`：30 个 MCP 工具的完整清单与写入门禁
- `docs/compose.md`：Docker Compose 工具背后的 fnOS 端点与语义
- `docs/cli-upgrade.md`：官方 CLI 升级 playbook（升级前必读）
- `docs/frontend.md`：面板前端结构与视觉 token
- `docs/configuration.md`：配置文件、环境变量与面板设置页

## 结构

- `src/fnos_mcp/`：config / auth / panel_auth / token_store /
  profile_store / runner / locks / cli_adapter / cli_capabilities /
  probe / state_store / audit / tools / api / server
- `web/`：Jinja2 模板 + 静态资源（HTMX 已 vendored 在仓库内，
  无 CDN 依赖）
- `tests/`：假 CLI + pytest 套件 + 两个冒烟脚本
- `docker/`：构建期安装官方 CLI 的脚本（下载 + 哈希校验）

## 许可证

Apache License 2.0（见根目录 `LICENSE` 文件）。
