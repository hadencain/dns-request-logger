import json
from pathlib import Path
from src.logger import Logger


def test_write_creates_file(tmp_path):
    log = Logger(log_dir=str(tmp_path))
    assert log.path.exists()
    log.close()


def test_write_jsonl_format(tmp_path):
    log = Logger(log_dir=str(tmp_path))
    event = {"timestamp": "2026-01-01T00:00:00Z", "domain": "example.com", "query_type": "A", "pid": 1234}
    log.write(event)
    log.close()

    lines = log.path.read_text().strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["domain"] == "example.com"
    assert record["qtype"] == "A"
    assert record["pid"] == 1234
    assert record["ts"] == "2026-01-01T00:00:00Z"


def test_write_multiple_events(tmp_path):
    log = Logger(log_dir=str(tmp_path))
    events = [
        {"timestamp": f"2026-01-01T00:00:0{i}Z", "domain": f"d{i}.com", "query_type": "A", "pid": i}
        for i in range(3)
    ]
    for e in events:
        log.write(e)
    log.close()

    lines = log.path.read_text().strip().splitlines()
    assert len(lines) == 3


def test_path_includes_timestamp(tmp_path):
    log = Logger(log_dir=str(tmp_path))
    log.close()
    assert "session-" in log.path.name
    assert log.path.suffix == ".jsonl"
