import datetime

from rich import box
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.analyzer import Analyzer

MAX_DOMAIN_ROWS = 40


class TUI:
    def __init__(self, analyzer: Analyzer) -> None:
        self._analyzer = analyzer
        self._start_time = datetime.datetime.now()

    def build(self) -> Layout:
        snap = self._analyzer.snapshot()
        layout = Layout()
        layout.split_column(
            Layout(name="top", ratio=9),
            Layout(name="status", size=3),
        )
        layout["top"].split_row(
            Layout(name="domains", ratio=2),
            Layout(name="flagged", ratio=1),
        )
        layout["domains"].update(self._domains_panel(snap))
        layout["flagged"].update(self._flagged_panel(snap))
        layout["status"].update(self._status_bar(snap))
        return layout

    def _domains_panel(self, snap: dict) -> Panel:
        table = Table(box=box.SIMPLE, expand=True, show_header=True, header_style="bold cyan")
        table.add_column("Domain", style="cyan", no_wrap=True)
        table.add_column("Freq", justify="right", style="white", width=6)
        table.add_column("Type", justify="center", style="dim", width=8)
        sorted_domains = sorted(snap["domains"].items(), key=lambda x: x[1], reverse=True)
        for domain, count in sorted_domains[:MAX_DOMAIN_ROWS]:
            meta = snap["meta"].get(domain, {})
            qtypes = ",".join(sorted(meta.get("query_types", {"?"})))
            table.add_row(domain, str(count), qtypes)
        return Panel(table, title="[bold cyan]DNS Queries[/]", border_style="cyan")

    def _flagged_panel(self, snap: dict) -> Panel:
        table = Table(box=box.SIMPLE, expand=True, show_header=False)
        table.add_column("Domain", style="yellow", no_wrap=True)
        table.add_column("Flags", style="bold red", width=14)
        hard_flagged = [
            (d, m)
            for d, m in snap["meta"].items()
            if m["flags"] - {"NEW"}
        ]
        hard_flagged.sort(key=lambda x: snap["domains"].get(x[0], 0), reverse=True)
        for domain, meta in hard_flagged:
            hard_flags = meta["flags"] - {"NEW"}
            flag_str = " ".join(f"[{f}]" for f in sorted(hard_flags))
            table.add_row(domain, flag_str)
        return Panel(table, title="[bold red]⚠ Flagged[/]", border_style="red")

    def _status_bar(self, snap: dict) -> Panel:
        elapsed = datetime.datetime.now() - self._start_time
        uptime = str(elapsed).split(".")[0]
        text = Text()
        text.append(f"Session: {uptime}", style="green")
        text.append("  |  ")
        text.append(f"Total queries: {snap['total']}", style="white")
        text.append("  |  ")
        dropped_style = "bold red" if snap["dropped"] > 0 else "dim"
        text.append(f"Dropped: {snap['dropped']}", style=dropped_style)
        return Panel(text, border_style="dim")
