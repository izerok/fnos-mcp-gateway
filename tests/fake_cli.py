#!/usr/bin/env python3
"""Fake fnos-cli 0.6.2 for M1 tests and smoke runs (tests/fake_cli.py).

NOT a real CLI. It implements the same argv surface the adapter uses
and records every invocation (argv + profile) to FNOS_FAKE_ARGV_LOG.
Per-profile login state lives in FNOS_FAKE_STATE_FILE (JSON).

Behaviour:
- --version -> "fnos-cli 0.6.2"
- login --authorize-only -> JSON with authorization_url
  (also accepts --agent-name/--device-name, as 0.6.2 does)
- login --code 000000 -> exit 1, code_invalid, token_persisted=false
- login --code expired-code -> exit 1, code_expired
- login --code consumed-code -> exit 1 BUT token_persisted=true
  (exercises the "code already consumed" path)
- login --code <anything else> -> token_persisted=true, logged in
- user info -> when logged in, the real NAS shape
  {"result":"succ","userInfo":{"user":"admin","admin":true,"uid":1000,
  "gid":1000,"groups":[...]}} by default (FR-37 detail extraction);
  the flat legacy {"identity":"admin"} shape is available via the
  state-file flag "user_info_flat": true. Not logged in -> the
  documented "saved proxy session is required" on stdout, exit 1
- system info -> canned JSON, never requires a session
- storage/file/docker/monitor -> canned JSON
"""

import json
import os
import sys


def _state_path():
    # State lives under FNOS_CLI_CONFIG_DIR, which the runner always
    # passes (whitelisted env) — never via test-only env vars.
    return os.path.join(os.environ.get("FNOS_CLI_CONFIG_DIR", "/tmp"),
                        "fake-state.json")


def _argv_log_path():
    return os.path.join(os.environ.get("FNOS_CLI_CONFIG_DIR", "/tmp"),
                        "fake-argv.log")


def _load_state():
    try:
        with open(_state_path(), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _save_state(state):
    with open(_state_path(), "w", encoding="utf-8") as fh:
        json.dump(state, fh)


def _log_argv(argv):
    path = _argv_log_path()
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"argv": argv}) + "\n")


def _opt(argv, name, default=None):
    if name in argv:
        i = argv.index(name)
        if i + 1 < len(argv):
            return argv[i + 1]
    return default


def main(argv):
    _log_argv(argv)
    if "--version" in argv:
        print("fnos-cli 0.6.2")
        return 0
    if "--help" in argv or "help" in argv:
        print("Usage: fnos-cli [OPTIONS] <COMMAND>\n\nCommands:\n"
              "  login     Log in via OAuth\n  logout    Log out (local session only)\n"
              "  user      User commands\n  system    System commands\n"
              "  storage   Storage commands\n  file      File commands\n"
              "  docker    Docker commands\n  monitor   Monitor commands\n")
        return 0
    profile = _opt(argv, "--profile", "default")
    host = _opt(argv, "--host", "localhost")
    port = _opt(argv, "--port", "5667")
    scheme = _opt(argv, "--scheme", "https")
    state = _load_state()
    prof_state = state.setdefault(profile, {"logged_in": False})

    def _emit(obj):
        print(json.dumps(obj))

    if argv[:1] == ["login"] or "login" in argv:
        if "--authorize-only" in argv:
            # 0.6.2 accepts --agent-name/--device-name; the fake CLI
            # ignores them (device naming is a NAS-side display concern).
            # Tests may inject a hostile authorization_url via the state
            # file (auth_url) to exercise FR-21 rejection; default is the
            # matching target origin.
            override = prof_state.get("auth_url")
            url = override or (
                f"{scheme}://{host}:{port}/oauth/authorize?client_id=TESTCLIENT"
                "&code_challenge=testchallenge&code_challenge_method=S256"
                "&state=teststate&scope=trim.user.all")
            _emit({"authorization_url": url, "client_id": "TESTCLIENT"})
            return 0
        if "--code" in argv:
            code = _opt(argv, "--code", "")
            if code == "000000":
                _emit({"error_code": "code_invalid", "token_persisted": False,
                       "refresh_token_persisted": False})
                return 1
            if code == "expired-code":
                _emit({"error_code": "code_expired", "token_persisted": False,
                       "refresh_token_persisted": False})
                return 1
            prof_state["logged_in"] = True
            _save_state(state)
            if code == "consumed-code":
                _emit({"token_persisted": True, "refresh_token_persisted": True})
                return 1
            _emit({"token_persisted": True, "refresh_token_persisted": True})
            return 0
    if "logout" in argv:
        prof_state["logged_in"] = False
        _save_state(state)
        _emit({"ok": True})
        return 0
    if argv[-2:] == ["user", "info"] or ("user" in argv and "info" in argv):
        # Tests inject auth_mode via the state file to exercise the
        # expired / permission branches of the adapter mapping.
        mode = prof_state.get("auth_mode")
        if mode == "expired":
            _emit({"error_code": "session_expired", "result": "error"})
            return 1
        if mode == "permission":
            _emit({"error_code": "permission_denied", "result": "error"})
            return 1
        if prof_state["logged_in"]:
            # Default mimics the real NAS: {"result":"succ","userInfo":{...}}
            # with uid/admin/groups, so FR-37 detail extraction is exercised
            # by every login-flow test. A state override can force the flat
            # legacy shape ("identity": "admin") via "user_info_flat": true.
            if prof_state.get("user_info_flat"):
                _emit({"identity": "admin", "user": "admin", "result": "ok"})
            else:
                _emit({"result": "succ", "userInfo": {
                    "user": "admin", "admin": True, "uid": 1000, "gid": 1000,
                    "groups": ["administrators", "users"]}})
            return 0
        print("saved proxy session is required")
        return 1
    if "system" in argv and "info" in argv:
        _emit({"machine": "fnOS", "version": "1.2.0800", "result": "ok"})
        return 0
    if "storage" in argv and "overview" in argv:
        _emit({"pools": 1, "total_bytes": 1000, "result": "ok"})
        return 0
    if "storage" in argv and "pools" in argv:
        _emit({"pools": [{"name": "pool1"}], "result": "ok"})
        return 0
    if "storage" in argv and "disks" in argv:
        _emit({"disks": [{"name": "sda"}], "result": "ok"})
        return 0
    if "file" in argv and "ls" in argv:
        _emit({"path": argv[-1], "entries": [{"name": "vol1", "type": "dir"}], "result": "ok"})
        return 0
    if "docker" in argv and "container" in argv and "ls" in argv:
        # The adapter calls `docker container ls` (fnos-cli has no
        # `docker ps`); shape follows the real CLI's list output.
        _emit([{"Names": ["/demo"], "State": "running", "Id": "abc123"}])
        return 0
    # --- deploy/write surface (M3-deploy) ---------------------------------
    if "file" in argv and "mkdir" in argv:
        _emit({"result": "succ", "path": argv[argv.index("mkdir") + 1]})
        return 0
    if "file" in argv and "upload" in argv:
        _emit({"result": "succ", "uploaded": argv[argv.index("upload") + 2]})
        return 0
    if "file" in argv and "chown" in argv:
        _emit({"result": "succ"})
        return 0
    if "docker" in argv and "container" in argv and "create" in argv:
        _emit({"Id": "newcontainer123", "Warnings": []})
        return 0
    if "docker" in argv and "container" in argv and "rm" in argv:
        _emit({"result": "succ"})
        return 0
    if "docker" in argv and "request" in argv:
        ep = argv[argv.index("request") + 1]
        # Compose endpoints answer with the real NAS shapes (verified
        # live 2026-11-25): list/containers/log are bare arrays, the
        # create/lifecycle calls answer with an errno envelope.
        if ep.endswith("composeList"):
            _emit([{"Name": "demo", "Folder": "vol1/1000/docker/demo",
                    "ConfigFiles": "vol1/1000/docker/demo/compose.yaml",
                    "Status": "ready", "Containers": {"running": 1, "total": 1}}])
            return 0
        if ep.endswith("composeContainers"):
            _emit([{"Id": "abc123", "Names": "demo", "State": "running",
                    "Status": "Up 2 hours"}])
            return 0
        if ep.endswith("composeLog"):
            _emit([" Container demo  Started\nExited:0"])
            return 0
        if ep.endswith("composeExistingFile"):
            _emit({"ConfigFiles": "compose.yaml"})
            return 0
        _emit({"req": ep, "errno": 0, "result": "succ"})
        return 0
    if "monitor" in argv and "cpu" in argv:
        _emit({"cpu_percent": 3.5, "result": "ok"})
        return 0
    print(json.dumps({"error_code": "unknown_command", "result": "error"}))
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
