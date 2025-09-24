#!/usr/bin/env python3
import sys, re

def parse_alerts(fp):
    ts_re = re.compile(r'^\d{4}-\d{2}-\d{2}T\S+$')
    ora_re = re.compile(r'^(ORA-\d{5}):\s*(.*)$')

    current_ts = None
    # key: code -> {'first': ts, 'last': ts, 'info': info, 'count': n}
    agg = {}

    def is_earlier(a, b):
        # Compare ISO-8601 strings; handle None safely. Return True if a < b.
        if a is None and b is None: return False
        if a is None: return False
        if b is None: return True
        return a < b  # ISO-8601 lexicographic order works

    def is_later(a, b):
        # Compare ISO-8601 strings; handle None safely. Return True if a > b.
        if a is None and b is None: return False
        if a is None: return True
        if b is None: return False
        return a > b

    for raw in fp:
        line = raw.rstrip('\n')
        if ts_re.match(line):
            current_ts = line.strip()
            continue

        m = ora_re.match(line)
        if m:
            code = m.group(1).strip()
            info = m.group(2).strip()

            if code not in agg:
                agg[code] = {'first': current_ts, 'last': current_ts, 'info': info, 'count': 1}
            else:
                # bump count
                agg[code]['count'] += 1
                
                # if this occurrence is earlier, update 'first' and 'info'
                if is_earlier(current_ts, agg[code]['first']):
                    agg[code]['first'] = current_ts
                    agg[code]['info'] = info
                # if existing first is None and current has ts, take it
                elif agg[code]['first'] is None and current_ts is not None:
                    agg[code]['first'] = current_ts
                    agg[code]['info'] = info

                # if this occurrence is later, update 'last'
                if is_later(current_ts, agg[code]['last']):
                    agg[code]['last'] = current_ts
                # if existing last is None and current has ts, take it
                elif agg[code]['last'] is None and current_ts is not None:
                    agg[code]['last'] = current_ts

    return agg

def main():
    if len(sys.argv) < 2:
        print("Usage: alert_log_check.py <alert_log_file> [--no-header]")
        sys.exit(1)

    path = sys.argv[1]
    show_header = True
    if len(sys.argv) > 2 and sys.argv[2] == "--no-header":
        show_header = False

    with open(path, 'r', encoding='utf-8', errors='replace') as fp:
        agg = parse_alerts(fp)

    # Sort by first occur (ascending), None last; tie-break by code
    items = sorted(
        agg.items(),
        key=lambda item: (
            item[1]['first'] is None,
            item[1]['first'] or 'ZZZ',
            item[0]
        )
    )

    # Emit CSV
    if show_header:
        print("Alert code,Alert info,first occur,last occur,count")
    for code, meta in items:
        info = (meta['info'] or "").replace('\n',' ').replace('\r',' ')
        first = meta['first'] or ""
        last = meta['last'] or ""
        print(f"{code},{info},{first},{last},{meta['count']}")

if __name__ == "__main__":
    main()