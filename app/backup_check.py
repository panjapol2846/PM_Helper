
#!/usr/bin/env python3
"""
Check RMAN backup logs to ensure the latest backup is within 7 days of the log's collection date.

Usage:
  python check_backups.py <log1> [<log2> ...] [--days 7] [--collection "YYYY-MM-DD HH:MM:SS"]

Rules:
- "Collection date" is taken from the RMAN banner line:
    "Recovery Manager: Release ... - Production on Wed Sep 10 13:43:10 2025"
  If that is missing, it falls back to the file's modification time.
- "Latest backup time" is the newest timestamp in format YYYY-MM-DD HH:MM:SS
  found anywhere in the file (covers Completion Time rows).
- Prints:
    ✅ file_name  Backup newer than 1 weeks | Latest: YYYY-MM-DD HH:MM:SS | Collection: YYYY-MM-DD HH:MM:SS (source)
    ❌ file_name  Backup is older than 1 weeks | Latest: YYYY-MM-DD HH:MM:SS | Collection: YYYY-MM-DD HH:MM:SS (source)
  (Threshold can be changed via --days, message still says "1 weeks" to match requested format.)
"""
import argparse
import re
from datetime import datetime, timedelta
from pathlib import Path
import sys

RMAN_COLLECTION_RE = re.compile(
    r'Production on ([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})'
)
# Examples in logs: 2025-07-07 04:20:59
YMD_HMS_RE = re.compile(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})')

def parse_args():
    p = argparse.ArgumentParser(add_help=True)
    p.add_argument('paths', nargs='+', help='Paths to RMAN log files')
    p.add_argument('--days', type=int, default=7, help='Warning threshold in days (default 7)')
    p.add_argument('--collection', type=str, default=None,
                   help='Override collection datetime (YYYY-MM-DD HH:MM:SS)')
    return p.parse_args()

def extract_collection_date(text: str, fallback_path: Path):
    """Return (dt, source) where source is 'banner', 'override', or 'mtime'."""
    m = RMAN_COLLECTION_RE.search(text)
    if m:
        try:
            dt = datetime.strptime(m.group(1), '%a %b %d %H:%M:%S %Y')
            return dt, 'banner'
        except ValueError:
            pass
    # Fallback to file mtime
    return datetime.fromtimestamp(fallback_path.stat().st_mtime), 'mtime'

def extract_latest_backup_time(text: str):
    # Grab all YYYY-MM-DD HH:MM:SS and take the max.
    candidates = []
    for m in YMD_HMS_RE.finditer(text):
        try:
            candidates.append(datetime.strptime(m.group(1), '%Y-%m-%d %H:%M:%S'))
        except ValueError:
            continue
    if not candidates:
        return None
    return max(candidates)

def fmt(dt: datetime | None) -> str:
    return dt.strftime('%Y-%m-%d %H:%M:%S') if dt else 'N/A'

def check_file(path: Path, threshold_days: int, override_collection: datetime | None) -> str:
    try:
        raw = path.read_text(errors='ignore')
    except Exception as e:
        return f'❌ {path.name} Failed to read file: {e}'

    collection_dt, source = extract_collection_date(raw, path)
    if override_collection is not None:
        collection_dt, source = override_collection, 'override'

    latest_backup_dt = extract_latest_backup_time(raw)

    if latest_backup_dt is None:
        return (f'❌ {path.name} No backup timestamps found | Latest: N/A | '
                f'Collection: {fmt(collection_dt)} ({source})')

    # If the log "collection time" is earlier than the latest timestamp found (shouldn't happen),
    # clamp the age to 0 days.
    age = max(timedelta(0), collection_dt - latest_backup_dt)

    prefix = (f'✅ {path.name}  Backup newer than 1 weeks'
              if age <= timedelta(days=threshold_days)
              else f'❌ {path.name} Backup is older than 1 weeks')

    return (f'{prefix} | Latest: {fmt(latest_backup_dt)} | '
            f'Collection: {fmt(collection_dt)} ({source})')

def main():
    args = parse_args()
    override_collection = None
    if args.collection:
        try:
            override_collection = datetime.strptime(args.collection, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            print('Invalid --collection format. Use "YYYY-MM-DD HH:MM:SS"', file=sys.stderr)
            sys.exit(2)

    for p in args.paths:
        path = Path(p)
        print(check_file(path, args.days, override_collection))

if __name__ == '__main__':
    main()
