"""Stable error codes (需求文档 §10.6 / §16.4). One code, one Chinese message.

HTTP mapping is fixed here so panel, MCP and tests can never drift apart.
"""

ERRORS = {
    "auth.required": (401, "登录已失效，请重新登录面板。", True),
    "auth.invalid": (401, "面板密码不正确。", True),
    "auth.forbidden": (403, "当前 token 没有这个操作权限。", False),
    "password.invalid": (400, "密码不符合要求。", False),
    "password.wrong": (400, "当前密码不正确。", False),
    "setup.done": (409, "管理员密码已设置，请直接登录。", False),
    "token.not_found": (404, "找不到这个密钥。", False),
    "token.invalid": (400, "密钥配置不合法，请检查名称和 ACL。", False),
    "token.limit": (409, "密钥数量已达到上限。", False),
    "token.unavailable": (409, "这把密钥创建于旧版本或会话密钥已更换，明文不可读取；轮换后可复制。", False),
    "profile.not_found": (404, "找不到这台机器，或当前 token 无权访问。", False),
    "profile.config_error": (None, "这台机器的配置不完整，已跳过。", False),
    "profile.invalid": (400, "机器配置不合法，请检查机器名、地址和端口。", False),
    "profile.exists": (409, "机器名已存在，换一个名字。", False),
    "probe.busy": (409, "这台机器正在测试网络，请稍后再试。", True),
    "session.locked": (409, "这台机器正在执行登录或连接测试，请稍后再试。", True),
    "probe.timeout": (None, "连接超时。", True),
    "probe.dns_failed": (None, "域名解析失败。", True),
    "probe.refused": (None, "连接被拒绝。", True),
    "probe.tls_failed": (None, "证书校验或 TLS 握手失败。", False),
    "probe.http_failed": (None, "目标返回了异常 HTTP 状态。", True),
    "login.code_invalid": (400, "授权码无效，请重新发起授权。", True),
    "login.code_expired": (400, "授权码已过期，请重新发起授权。", True),
    "login.failed": (502, "登录没有完成，NAS 端可能拒绝或网络中断。", True),
    "logout.failed": (500, "本机 session 清理失败，请重试；NAS 端授权未改变。", True),
    "rate_limited": (429, "操作太频繁，请稍后再试。", True),
    "internal": (500, "面板内部错误，请查看容器日志。", True),
    "profile.required": (400, "请指定一台机器。", True),
    "invalid_params": (400, "请求参数不正确。", False),
}


class ApiError(Exception):
    """An error that maps 1:1 onto a stable error code."""

    def __init__(self, code: str, details: dict | None = None):
        assert code in ERRORS, f"unknown error code {code!r}"
        self.code = code
        self.http_status, self.message, self.retryable = ERRORS[code]
        # details: whitelist only (sub_reason / http_status / latency_ms / retry_after)
        self.details = {k: v for k, v in (details or {}).items()
                        if k in ("sub_reason", "http_status", "latency_ms", "retry_after")}
        super().__init__(f"{code}: {self.message}")


class ConfigError(Exception):
    """File-level configuration error: startup must fail."""


class CliError(Exception):
    """The CLI call itself failed (not a business outcome)."""


class CliVersionError(CliError):
    """CLI --version is not a supported version: startup must fail."""


class LockedError(Exception):
    """A per-profile lock is already held; caller maps to 409."""

    def __init__(self, lock_kind: str):
        self.lock_kind = lock_kind  # "probe" or "session"
        super().__init__(f"{lock_kind} lock held")
