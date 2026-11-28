# 前端依赖（本地分发，无 CDN）

## HTMX

- 版本：**2.0.7**，文件 `web/static/htmx.min.js`（51,076 字节）
- 来源：`https://unpkg.com/htmx.org@2.0.7/dist/htmx.min.js`（2026-11-23 下载）
- SHA-256：`60231ae6ba9db3825eb15a261122d5f55921c4d53b66bf637dc18b4ee27c79f9`
- 核对：文件头为 htmx 2.0.7 的压缩源码；`app.js` 在 htmx 未加载时直接返回，不伪造 HTMX。
- 升级：换文件后更新此处版本号与 SHA-256，并重跑面板测试。

## FastMCP 2（MCP 传输层）

- 钉死版本：`fastmcp==2.10.6`、`mcp==1.30.0`（见 `pyproject.toml`）
- 兼容组合（实测）：fastmcp 2.10.6 + `pydantic==2.11.10` +
  `pydantic-settings==2.10.1` + `starlette==0.41.3` + `uvicorn==0.34.0`。
  注意：fastmcp 2.14.7 会把 starlette 升到 1.10，与 FastAPI 0.115.6
  冲突；pydantic >= 2.12 会让 fastmcp 2.10.6 的 Settings 导入失败。
  升级任一成员前，先在 venv 里跑全量 pytest 再定。
- 传输：Streamable HTTP，挂载于 `/mcp`；鉴权由 server.py 的
  `_McpAuthApp`（Bearer）做，工具逻辑在 `tools/registry.py` 不动。

## 剪贴板（访问密钥 / 授权链接 / 客户端配置）

- 面板常用 HTTP + 局域网 IP 打开，不是安全上下文，`navigator.clipboard`
  不存在。`app.js` 的 `copyText()` 先用 Clipboard API，失败后回退到
  临时 textarea + `document.execCommand("copy")`。
- 仍失败时不静默：密钥会全选 `.token-plain`；含密钥的客户端配置会展开
  `#tokenClientConfig` 并全选；列表页则把拉取到的内容放进管理员弹窗并全选，
  提示手动复制。
- 一次性密钥视图提供“复制密钥”和“复制客户端配置”（含 MCP 地址与
  `Authorization: Bearer <key>`），配置由服务端渲染进隐藏 `<pre>`，
  JS 只读 `textContent`，不把密钥拼进脚本字符串。
- 访问密钥列表每行有“复制密钥”“复制 JSON”：点击时 `fetch`
  `/api/tokens/{id}/secret`（`no-store`，需面板会话），返回明文与
  `mcpServers` JSON 后走同一套复制逻辑；旧版 seed key 没有密文，行上
  标记“早期密钥”且不显示复制按钮，接口返回 `token.unavailable`。
- 成功时按钮短暂显示“已复制”（`aria-live` 同步），1.8s 后恢复。
- 关闭一次性密钥弹窗或手动复制弹窗时清空 `#adminModalBody`，避免明文
  留在隐藏 DOM。编辑密钥或修改密码保存后，HTMX 处理带外片段时可能再对
  `#adminModalBody` 触发一次空内容的 `afterSwap`；`afterSwap` 只在目标
  仍有内容时才打开弹窗，不会留下空白弹窗。

## 机器列表与页面布局（M5.z）

- 每行三段：左侧状态轨、中间主区、右侧操作。主区第一行是名称、状态徽标
  与不安全连接标签；第二行把地址和元信息（TLS、状态原因、上次检查、耗时）
  放在同一行，空间不足时自动换行。
- 网络不可达的原因只在元信息里出现一次（如“连接超时”）；TLS/协议错误和
  配置错误才在下方单独显示详细原因。
- ≤860px 操作区移到主区下方并左对齐；≤680px 操作按钮改为
  `auto-fit minmax(96px,1fr)` 的等宽网格，375/320px 无横向滚动。
- “机器”“访问密钥”标题带数量徽标；`.paper` 设 `scroll-margin-top:72px`，
  程序化滚动或锚点不会把标题压到 48px 顶栏下面。
- 拓扑与 MCP 双卡改为各自高度（`align-items:start`），折叠的拓扑不再被
  拉成与 MCP 等高的空白卡片。

## 布局 M7：顶部导航 + 双栏工作区 + 能力页

- 顶栏加了 `.mainnav`（机器 / 能力）分段导航，右侧保留状态、CLI、身份与
  操作；`aria-current="page"` 标当前页，“能力”标签带工具数徽标。未登录
  （登录页）不显示导航。
- 机器页改为 `.workspace` 双栏：左侧主列是机器列表与访问密钥，右侧
  `.workspace-side` 是 MCP 接入卡、拓扑卡与能力速览卡（链到 `/capabilities`）。
  ≥1025px 时侧栏 sticky（`top:72px`），窄屏按列堆叠、侧栏在前。
- 每页有 `.page-head`（eyebrow + h1 + lede）与右上动作区（如“下载 JSON”）。
- 能力页 `/capabilities`：运行时条（cli 版本、工具数读/写、Compose 数、
  数据目录、MCP 地址与传输）、当前身份 KV、按组折叠的工具目录（组头显示
  “只读 N · 写 N”，组内每个工具是 `<details>`：参数表 + 嵌套 JSON Schema
  默认收起）、机器授权表（`allow_dangerous` 已解锁/未开启、`tls_insecure`
  标签）、MCP 接入块。
- 窄屏：≤680px 顶栏 `height:auto` 并允许换行，导航整行排第三；指标
  `.rollup` 隐藏；`h1` 降到 32px；`pre` 横向滚动；授权表 `th/td` 不换行，
  徽标 `nowrap`，避免出现“未 测 试”竖排；`cap-table-wrap` 支持触控惯性滚动。
- 目录数据来自 `tools/registry.py` 的 `tool_catalog()`，测试断言页面里的
  工具名与 MCP 实际暴露一致，UI 不会与注册表漂移。

## 触控目标取舍（v2，StyleKit Apple token）

- 桌面按钮 36–40px（`.btn` 40px、`.btn.small` 36px），主按钮带系统蓝光晕。
- 触控设备（`pointer:coarse`）与窄屏（≤680px）下，按钮补到 44px 高。
  分段选择器按钮窄屏保持 36px（见 `docs/ui-mock/NOTES-v2.md` §6）。
  唯一例外：顶栏两个操作（修改密码 / 退出面板）在 ≤680px 压到 34px，
  否则 375px 视口放不下品牌 + 两个按钮。
- 视觉 token：画布 `#f5f5f7`、卡片纯白 24px 圆角、唯一强调色 `#0071e3`
  （hover `#0077ed`）；状态色绿 `#34c759` / 琥珀 `#ff9500` / 红 `#ff3b30` /
  灰 `#8e8e93`，状态文字用加深版；毛玻璃只在 48px 顶栏，`@supports not
  (backdrop-filter)` 与 `prefers-reduced-transparency` 时回纯白。
