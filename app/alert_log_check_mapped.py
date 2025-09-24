#!/usr/bin/env python3
import sys, re, csv

def parse_alerts(fp):
    ts_re = re.compile(r'^\d{4}-\d{2}-\d{2}T\S+$')
    ora_re = re.compile(r'^(ORA-\d{5}):\s*(.*)$')

    current_ts = None
    # key: code -> {'first': ts_or_none, 'info': info_of_first, 'count': n}
    agg = {}

    def is_earlier(a, b):
        if a is None and b is None: return False
        if a is None: return False
        if b is None: return True
        return a < b

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
                agg[code] = {'first': current_ts, 'info': info, 'count': 1}
            else:
                agg[code]['count'] += 1
                if is_earlier(current_ts, agg[code]['first']):
                    agg[code]['first'] = current_ts
                    agg[code]['info'] = info
                elif agg[code]['first'] is None and current_ts is not None:
                    agg[code]['first'] = current_ts
                    agg[code]['info'] = info
    return agg

def sniff_encoding(path):
    try:
        with open(path, 'rb') as bf:
            head = bf.read(4)
        if head.startswith(b'\xff\xfe') or head.startswith(b'\xfe\xff'):
            return 'utf-16'
        if head.startswith(b'\xef\xbb\xbf'):
            return 'utf-8-sig'
    except Exception:
        pass
    return 'utf-8'

def load_mapping(map_path):
    mapping = {}
    if not map_path:
        return mapping
    enc = sniff_encoding(map_path)
    with open(map_path, 'r', encoding=enc, errors='replace', newline='') as f:
        reader = csv.DictReader(f)
        field_map = { (name or '').strip().lower(): name for name in reader.fieldnames or [] }
        code_key = field_map.get('code')
        cause_key = field_map.get('cause')
        action_key = field_map.get('action')
        if not code_key:
            raise ValueError("Mapping file must have a 'code' column")
        for row in reader:
            code = (row.get(code_key) or '').strip()
            if not code: 
                continue
            mapping[code] = {
                'cause': (row.get(cause_key) or '').strip() if cause_key else '',
                'action': (row.get(action_key) or '').strip() if action_key else '',
            }
    return mapping

def main():
    if len(sys.argv) < 2:
        print("Usage: alert_log_check_mapped.py <alert_log_file> [--no-header] [--map mapping.csv]")
        sys.exit(1)

    path = sys.argv[1]
    show_header = True
    map_path = None

    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--no-header":
            show_header = False
            i += 1
        elif sys.argv[i] == "--map" and i + 1 < len(sys.argv):
            map_path = sys.argv[i + 1]
            i += 2
        else:
            i += 1

    with open(path, 'r', encoding='utf-8', errors='replace') as fp:
        agg = parse_alerts(fp)

    items = sorted(
        agg.items(),
        key=lambda item: (
            item[1]['first'] is None,
            item[1]['first'] or 'ZZZ',
            item[0]
        )
    )

    mapping = load_mapping(map_path)

    w = csv.writer(sys.stdout, lineterminator='\n')
    header = ["Alert code","Alert info","first occur","count","cause","action"]
    if show_header:
        w.writerow(header)

    for code, meta in items:
        m = mapping.get(code, {})
        w.writerow([
            code,
            meta['info'] or '',
            meta['first'] or '',
            meta['count'],
            m.get('cause',''),
            m.get('action',''),
        ])

if __name__ == "__main__":
    main()
