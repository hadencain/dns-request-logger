import json
from datetime import datetime
from pathlib import Path


class Logger:
    def __init__(self, log_dir: str = "logs"):
        Path(log_dir).mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        self._path = Path(log_dir) / f"session-{ts}.jsonl"
        self._file = open(self._path, "w", encoding="utf-8")

    def write(self, event: dict) -> None:
        record = {
            "ts": event["timestamp"],
            "domain": event["domain"],
            "qtype": event["query_type"],
            "pid": event["pid"],
        }
        self._file.write(json.dumps(record) + "\n")
        self._file.flush()

    def close(self) -> None:
        self._file.close()

    @property
    def path(self) -> Path:
        return self._path
