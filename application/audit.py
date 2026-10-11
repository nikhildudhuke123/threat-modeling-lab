import json
import logging
from datetime import datetime, timezone

audit_logger = logging.getLogger("securebank.audit")


def audit_event(event, outcome, **details):
    """Write structured security events without secrets or sensitive values."""
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "outcome": outcome,
        **details,
    }

    audit_logger.info(json.dumps(record, sort_keys=True))
