import hashlib
import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

audit_logger = logging.getLogger("securebank.audit")
audit_logger.setLevel(logging.INFO)
audit_logger.propagate = False

_lock = threading.Lock()
_LOG_DIR = Path(os.environ.get("AUDIT_LOG_DIR", "logs"))
_LOG_FILE = _LOG_DIR / "audit.log"
_ZERO_HASH = "0" * 64


def _canonical_json(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


def audit_event(event, outcome, **details):
    """Persist a structured, hash-chained security event.

    Callers must supply only approved, non-sensitive metadata.
    """
    safe_details = {
        key: value
        for key, value in details.items()
        if key not in {
            "password", "password_hash", "token", "access_token",
            "authorization", "secret", "balance",
        }
    }

    with _lock:
        if not _LOG_DIR.exists():
            _LOG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not _LOG_DIR.is_dir():
            raise RuntimeError("Audit log path is not a directory")
        if os.name == "posix":
            directory_mode = _LOG_DIR.stat().st_mode & 0o777
            if directory_mode & 0o077:
                raise PermissionError(
                    "Audit log directory must not grant group or other access"
                )

        previous_hash = _ZERO_HASH
        if _LOG_FILE.exists():
            try:
                with _LOG_FILE.open("r", encoding="utf-8") as existing:
                    for line in existing:
                        if line.strip():
                            previous_hash = json.loads(line)["record_hash"]
            except (OSError, ValueError, KeyError) as exc:
                raise RuntimeError("Audit log is unreadable or malformed") from exc

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "outcome": outcome,
            "details": safe_details,
            "previous_hash": previous_hash,
        }
        record["record_hash"] = hashlib.sha256(
            _canonical_json(record).encode("utf-8")
        ).hexdigest()

        fd = os.open(
            _LOG_FILE,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o600,
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as output:
                fd = -1
                output.write(_canonical_json(record) + "\n")
                output.flush()
                os.fsync(output.fileno())
        finally:
            if fd != -1:
                os.close(fd)

        audit_logger.info(_canonical_json(record))


def verify_audit_log(path=None):
    """Check record hashes and previous-record links in the local log."""
    log_path = Path(path) if path is not None else _LOG_FILE
    previous_hash = _ZERO_HASH

    if not log_path.exists():
        return True

    with log_path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                actual_hash = record.pop("record_hash")
                if record.get("previous_hash") != previous_hash:
                    return False
                expected_hash = hashlib.sha256(
                    _canonical_json(record).encode("utf-8")
                ).hexdigest()
                if actual_hash != expected_hash:
                    return False
                previous_hash = actual_hash
            except (ValueError, KeyError, TypeError):
                return False

    return True
