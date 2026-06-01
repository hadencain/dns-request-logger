# DNS Request Logger

Live TUI that monitors DNS lookups on Windows, grouped by domain with frequency counts and anomaly highlighting.

## Requirements

- Windows 10/11
- Python 3.10+
- Administrator privileges

## Setup

```bash
python -m venv venv
source venv/Scripts/activate   # Windows bash
pip install -r requirements.txt
```

Enable the DNS Client event log (run once as admin):
```
wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true
```

## Run

```bash
python -m src.main
```

Must be run as administrator.

## Anomaly Flags

| Flag | Meaning |
|------|---------|
| `[ENT]` | High-entropy hostname label (possible DGA) |
| `[TLD]` | Uncommon or abused TLD |
| `[SUB]` | Deep subdomain chain (4+ labels) |
| `[NEW]` | Only seen once this session |

## Data Privacy

Session logs are written to `logs/` which is gitignored. No data is committed to the repository.
