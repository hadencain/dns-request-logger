import queue
import threading
import unittest.mock as mock
import sys

# Mock win32evtlog and win32event before importing reader
win32evtlog_mock = mock.MagicMock()
win32event_mock = mock.MagicMock()
sys.modules["win32evtlog"] = win32evtlog_mock
sys.modules["win32event"] = win32event_mock

from src.reader import EventReader, _parse_xml


SAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>3008</EventID>
    <TimeCreated SystemTime="2026-01-01T00:00:00.000Z"/>
    <Execution ProcessID="1234"/>
  </System>
  <EventData>
    <Data Name="QueryName">example.com.</Data>
    <Data Name="QueryType">1</Data>
  </EventData>
</Event>"""

SAMPLE_XML_UNKNOWN_ID = SAMPLE_XML.replace("<EventID>3008</EventID>", "<EventID>9999</EventID>")
SAMPLE_XML_NO_DOMAIN = SAMPLE_XML.replace("<Data Name=\"QueryName\">example.com.</Data>",
                                           "<Data Name=\"QueryName\"></Data>")


def test_parse_xml_returns_event():
    result = _parse_xml(SAMPLE_XML)
    assert result is not None
    assert result["domain"] == "example.com"
    assert result["pid"] == 1234
    assert result["timestamp"] == "2026-01-01T00:00:00.000Z"


def test_parse_xml_strips_trailing_dot():
    result = _parse_xml(SAMPLE_XML)
    assert not result["domain"].endswith(".")


def test_parse_xml_drops_unknown_event_id():
    result = _parse_xml(SAMPLE_XML_UNKNOWN_ID)
    assert result is None


def test_parse_xml_drops_empty_domain():
    result = _parse_xml(SAMPLE_XML_NO_DOMAIN)
    assert result is None


def test_parse_xml_handles_malformed():
    result = _parse_xml("not xml at all {{{{")
    assert result is None


def test_fanout_puts_to_all_queues():
    q1: queue.Queue = queue.Queue()
    q2: queue.Queue = queue.Queue()
    reader = EventReader(output_queues=[q1, q2])
    event = {"domain": "a.com", "query_type": "A", "pid": 1, "timestamp": "2026-01-01T00:00:00Z"}
    reader._fanout(event)
    assert q1.get_nowait() == event
    assert q2.get_nowait() == event


def test_fanout_drops_when_queue_full():
    q1: queue.Queue = queue.Queue(maxsize=1)
    q1.put("existing")
    reader = EventReader(output_queues=[q1])
    event = {"domain": "a.com", "query_type": "A", "pid": 1, "timestamp": "2026-01-01T00:00:00Z"}
    reader._fanout(event)
    assert reader.dropped == 1
    assert q1.qsize() == 1  # not grown


def test_eventreader_default_init():
    q = queue.Queue()
    reader = EventReader(output_queues=[q])
    assert reader.dropped == 0
