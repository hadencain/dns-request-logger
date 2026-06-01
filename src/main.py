import ctypes
import queue
import sys
import threading
import time

from rich import print as rprint
from rich.live import Live

from src.analyzer import Analyzer
from src.logger import Logger
from src.reader import EventReader
from src.tui import TUI


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def print_summary(analyzer: Analyzer, reader: EventReader) -> None:
    snap = analyzer.snapshot()
    total_dropped = snap["dropped"] + reader.dropped
    rprint(f"\n[bold]Session complete.[/]")
    rprint(f"Total queries: {snap['total']}  |  Dropped: {total_dropped}")
    rprint("\n[bold cyan]Top 10 domains:[/]")
    sorted_domains = sorted(snap["domains"].items(), key=lambda x: x[1], reverse=True)[:10]
    for domain, count in sorted_domains:
        rprint(f"  {count:>5}  {domain}")
    hard_flagged = [d for d, m in snap["meta"].items() if m["flags"] - {"NEW"}]
    rprint(f"\n[bold red]Flagged domains: {len(hard_flagged)}[/]")
    for d in hard_flagged:
        flags = " ".join(f"[{f}]" for f in sorted(snap["meta"][d]["flags"] - {"NEW"}))
        rprint(f"  {d}  {flags}")


def _worker(fn, stop_event: threading.Event) -> threading.Thread:
    def _run():
        while not stop_event.is_set():
            fn()
    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t


def main() -> None:
    if not is_admin():
        rprint("[bold red]Error:[/] DNS logger requires administrator privileges.")
        rprint("Right-click your terminal and select 'Run as administrator', then try again.")
        sys.exit(1)

    analyzer_q: queue.Queue = queue.Queue()
    log_q: queue.Queue = queue.Queue()

    analyzer = Analyzer()
    logger = Logger()
    reader = EventReader(output_queues=[analyzer_q, log_q])
    tui = TUI(analyzer)

    stop_event = threading.Event()

    def analyzer_loop():
        try:
            event = analyzer_q.get(timeout=0.1)
            analyzer.process(event)
        except queue.Empty:
            pass

    def logger_loop():
        try:
            event = log_q.get(timeout=0.1)
            logger.write(event)
        except queue.Empty:
            pass

    reader.start()
    reader._ready.wait(timeout=5)
    if reader._startup_error:
        rprint(f"[bold red]Error:[/] Could not subscribe to DNS event log: {reader._startup_error}")
        rprint("Enable with: wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true")
        sys.exit(1)

    _worker(analyzer_loop, stop_event)
    _worker(logger_loop, stop_event)

    rprint(f"[dim]Logging session to: {logger.path}[/]")
    rprint("[dim]Press Ctrl+C to stop.[/]\n")
    time.sleep(0.5)

    try:
        with Live(tui.build(), refresh_per_second=2, screen=True) as live:
            while True:
                live.update(tui.build())
                time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        reader.stop()
        reader.join(timeout=2)
        logger.close()
        print_summary(analyzer, reader)


if __name__ == "__main__":
    main()
