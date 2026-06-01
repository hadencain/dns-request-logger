import math
import threading
from collections import Counter
from typing import Dict, Set


SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ru", ".cn", ".pw",
    ".gq", ".ml", ".ga", ".cf",
}
ENTROPY_THRESHOLD = 3.2
MAX_LABELS = 4


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def run_heuristics(domain: str) -> Set[str]:
    flags: Set[str] = set()
    labels = domain.rstrip(".").split(".")
    tld = f".{labels[-1]}" if len(labels) >= 2 else ""
    if tld in SUSPICIOUS_TLDS:
        flags.add("TLD")
    if len(labels) > MAX_LABELS:
        flags.add("SUB")
    leftmost = labels[0] if labels else ""
    if shannon_entropy(leftmost) > ENTROPY_THRESHOLD:
        flags.add("ENT")
    return flags


class Analyzer:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counts: Counter = Counter()
        self._meta: Dict[str, dict] = {}
        self.total: int = 0
        self.dropped: int = 0

    def process(self, event: dict) -> None:
        domain = event["domain"]
        qtype = event["query_type"]
        ts = event["timestamp"]
        with self._lock:
            self.total += 1
            self._counts[domain] += 1
            if domain not in self._meta:
                flags = run_heuristics(domain)
                flags.add("NEW")
                self._meta[domain] = {
                    "count": 1,
                    "first_seen": ts,
                    "last_seen": ts,
                    "query_types": {qtype},
                    "flags": flags,
                }
            else:
                m = self._meta[domain]
                m["count"] += 1
                m["last_seen"] = ts
                m["query_types"].add(qtype)
                m["flags"].discard("NEW")

    def increment_dropped(self) -> None:
        with self._lock:
            self.dropped += 1

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "total": self.total,
                "dropped": self.dropped,
                "domains": dict(self._counts),
                "meta": {
                    k: {
                        **v,
                        "query_types": set(v["query_types"]),
                        "flags": set(v["flags"]),
                    }
                    for k, v in self._meta.items()
                },
            }
