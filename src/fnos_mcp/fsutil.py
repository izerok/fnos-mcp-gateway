"""Small filesystem helpers shared by the writable stores."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def atomic_write(path: str | Path, text: str) -> None:
    """Write ``text`` to ``path`` atomically with 0600 permissions."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.tmp-",
                                    dir=str(target.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, target)
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass
