import logging
import re
import sys
from datetime import datetime, timezone

import json as _json

_SECRET_RE = re.compile(
    r"(apikey|authorization|anon_key|api_key|bearer)[=:]?\s*\S+(\s+\S+)?",
    re.IGNORECASE,
)


def redact(text: str) -> str:
    return _SECRET_RE.sub(lambda m: f"{m.group(1)}=[REDACTED]", text)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "message": redact(record.getMessage()),
            "logger": record.name,
        }
        for key in ("target_host", "scan_id", "table_name"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        if record.exc_info:
            payload["exc_info"] = redact(self.formatException(record.exc_info))
        return _json.dumps(payload)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
