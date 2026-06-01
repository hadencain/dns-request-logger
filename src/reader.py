import queue
import threading
import xml.etree.ElementTree as ET

import win32evtlog
import win32event

CHANNEL = "Microsoft-Windows-DNS-Client/Operational"
EVT_QUERY_IDS = {3008, 3020}
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

QTYPE_NAMES = {
    "1": "A", "2": "NS", "5": "CNAME", "6": "SOA",
    "12": "PTR", "15": "MX", "16": "TXT", "28": "AAAA",
    "33": "SRV", "255": "ANY",
}


def _parse_xml(xml_str: str) -> dict | None:
    try:
        root = ET.fromstring(xml_str)
        eid = int(root.findtext(".//e:EventID", default="0", namespaces=NS))
        if eid not in EVT_QUERY_IDS:
            return None
        ts = root.find(".//e:TimeCreated", NS).get("SystemTime", "")
        pid = int(root.find(".//e:Execution", NS).get("ProcessID", "0"))
        data = {d.get("Name"): (d.text or "") for d in root.findall(".//e:Data", NS)}
        domain = data.get("QueryName", "").rstrip(".")
        if not domain:
            return None
        raw_qtype = data.get("QueryType", "1")
        qtype = QTYPE_NAMES.get(raw_qtype, raw_qtype)
        return {"domain": domain, "query_type": qtype, "pid": pid, "timestamp": ts}
    except Exception:
        return None


class EventReader(threading.Thread):
    def __init__(self, output_queues: list) -> None:
        super().__init__(daemon=True, name="dns-reader")
        self._queues = output_queues
        self._stop_evt = threading.Event()
        self._dropped: int = 0
        self._dropped_lock = threading.Lock()
        self._startup_error: Exception | None = None
        self._ready = threading.Event()

    @property
    def dropped(self) -> int:
        with self._dropped_lock:
            return self._dropped

    def stop(self) -> None:
        self._stop_evt.set()

    def run(self) -> None:
        try:
            signal = win32event.CreateEvent(None, False, False, None)
            sub = win32evtlog.EvtSubscribe(
                CHANNEL,
                win32evtlog.EvtSubscribeToFutureEvents,
                SignalEvent=signal,
            )
        except Exception as e:
            self._startup_error = e
            self._ready.set()
            return
        self._ready.set()
        try:
            while not self._stop_evt.is_set():
                win32event.WaitForSingleObject(signal, 500)
                while True:
                    events = win32evtlog.EvtNext(sub, 10, 0)  # 0 = nonblocking
                    if not events:
                        break
                    for raw in events:
                        try:
                            xml_str = win32evtlog.EvtRender(
                                raw, win32evtlog.EvtRenderEventXml
                            )
                        except Exception:
                            continue
                        parsed = _parse_xml(xml_str)
                        if parsed:
                            self._fanout(parsed)
        finally:
            win32evtlog.EvtClose(sub)
            win32event.CloseHandle(signal)

    def _fanout(self, event: dict) -> None:
        for q in self._queues:
            try:
                q.put_nowait(event)
            except queue.Full:
                with self._dropped_lock:
                    self._dropped += 1
