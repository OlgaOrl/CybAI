import json
import logging
import sys
import uuid
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {
                "trace_id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": record.levelname,
                "module": record.name,
                "message": record.getMessage(),
            }
        )


class _DynamicStderrHandler(logging.StreamHandler):
    """Always writes to current sys.stderr, supports test capture (capsys)."""

    def emit(self, record: logging.LogRecord) -> None:
        self.stream = sys.stderr
        super().emit(record)


def get_logger(module: str) -> logging.Logger:
    logger = logging.getLogger(module)
    if not logger.handlers:
        handler = _DynamicStderrHandler()
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        logger.propagate = False
    return logger
