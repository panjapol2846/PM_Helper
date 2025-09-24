#!/usr/bin/env python3
import argparse, io, os, re, sys, zipfile, csv, shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Tuple, Optional, Dict, Any

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

# ---- Import helpers next to this file ----
try: import config_check
except Exception: config_check = None
try: import awr_analyzer
except Exception: awr_analyzer = None
try: import table_space_check
except Exception: table_space_check = None
try: import backup_check
except Exception: backup_check = None
try: import alert_log_check_mapped as alert_map  # only for load_mapping()
except Exception: alert_map = None

# ---------- utils ----------
def safe_read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        try:
            return path.read_text(errors="ignore")
        except Exception:
            return ""

def write_file(path: Path, content: str, encoding: str="utf-8"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding=encoding)

def is_zip(p: Path) -> bool:
    try:
        return zipfile.is_zipfile(p)
    except Exception:
        return False

def extract_zip(zip_path: Path) -> Path:
    dest = zip_path.with_suffix("")
    dest = dest.parent / (dest.name + "_extracted")
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(dest)
    return dest

def find_first_level_used(root: Path) -> Path:
    cdbs = [p for p in root.iterdir() if p.is_dir() and p.name.upper().startswith("CDB")]
    if cdbs:
        return root

    # If there is a single child folder (wrapper) and it contains DB-like subfolders, descend into it
    children = [p for p in root.iterdir() if p.is_dir()]
    if len(children) == 1:
        child = children[0]
        try:
            grandkids = [g for g in child.iterdir() if g.is_dir()]
        except Exception:
            grandkids = []
        if any(((g / "auto_collection").exists() or (g / "report").exists() or (g / "log").exists()) for g in grandkids):
            return child
    
    # If there are subfolders, but the root itself doesn't contain a CDB folder, check for DB-like subfolders
    for child in children:
        if any((child / sub).exists() for sub in ("auto_collection", "report", "log")):
            return root

    pm_like = [p for p in root.iterdir() if p.is_dir() and p.name.lower().startswith("pm_")]
    if pm_like:
        return pm_like[0]

    return root

def list_database_dirs(first_level: Path) -> List[Path]:
    return [p for p in first_level.iterdir()
            if p.is_dir() and (
                (p / "auto_collection").exists() or (p / "report").exists() or (p / "log").exists()
            )]

# --- AWR scoring (choose best by DB Time) ---
_DB_TIME_INLINE = re.compile(r"DB\s*Time[:\s]*([\d,\.]+)\s*(hours?|hrs?|h|minutes?|mins?|m|seconds?|secs?|s)?", re.I)
def score_awr(html_path: Path) -> float:
    txt = safe_read_text(html_path)
    m = _DB_TIME_INLINE.search(txt)
    if m:
        val = float(str(m.group(1)).replace(",",""))
        unit = (m.group(2) or "").lower()
        if unit.startswith("h"): return val * 3600.0
        if unit.startswith("m") and unit != "": return val * 60.0
        return val
    if awr_analyzer:
        try:
            data = awr_analyzer.analyze(html_path)
            rows = data.get("Top 10 Foreground Events by Total Wait Time") or []
            total = 0.0
            for r in rows:
                v = r.get("total_wait_time_s")
                if isinstance(v,(int,float)): total += v
            if total > 0: return float(total)
        except Exception: pass
    return html_path.stat().st_mtime

# --- Alert log timestamp parsing ---
_TS_FORMATS = [
    "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
    "%a %b %d %H:%M:%S %Y %z", "%a %b %d %H:%M:%S %Y",
]
def parse_ts(line: str) -> Optional[datetime]:
    s = line.strip()
    if s.endswith("Z"): s = s[:-1] + "+00:00"
    for fmt in _TS_FORMATS:
        try: return datetime.strptime(s, fmt)
        except Exception: continue
    try: return datetime.fromisoformat(s)
    except Exception: return None

# ---------- Severity engine (Severity 1–4) ----------
SEV_LABEL = {
    1: "Severity 1 (urgent)",
    2: "Severity 2 (high)",
    3: "Severity 3 (medium)",
    4: "Severity 4 (low)",
}
def _status_from_sev(n: int) -> str:
    return "Normal" if n >= 4 else "Attention"
def _sev_label(n: int) -> str:
    return SEV_LABEL.get(n, "Severity 4 (low)")
def _desc_lines_from(text: str, max_lines: int=12) -> str:
    lines = [ln for ln in text.splitlines() if ln.strip() and "====" not in ln]
    return "\n".join(lines[:max_lines])

def severity_config(text: str) -> int:
    t = text.lower()
    bad_ctrl = "❌ control file" in t
    bad_redo = ("❌ redo" in t) or ("❌ redolog" in t) or ("❌ redo logs" in t)
    if bad_ctrl and bad_redo: return 1
    if bad_ctrl or bad_redo:  return 2
    if "❌ patches" in t:     return 4
    return 4

def severity_awr(text: str) -> int:
    import re
    if "❌" not in text: return 4
    m = re.search(r"❌.*?(\d+(?:\.\d+)?)%\s*DB\s*Time", text, re.I)
    if m:
        pct = float(m.group(1))
        if pct >= 50: return 2
        if pct >= 20: return 3
    lows = []
    for m in re.finditer(r"(\bHit Ratio\b.*?)(\d+(?:\.\d+)?)\s*%", text, re.I | re.DOTALL):
        try: lows.append(float(m.group(2)))
        except Exception: pass
    if lows and min(lows) < 50: return 3
    if "❌concerning running sql" in text.lower(): return 3
    return 4

def severity_tablespace(item_text: str) -> int:
    import re
    if "❌" not in item_text: return 4
    m = re.search(r"less\s+than\s+(\d+)\s*%?", item_text, re.I)
    if m:
        x = int(m.group(1))
        if x < 5:  return 1
        if x <=10: return 2
        if x <=15: return 3
        return 3
    return 3

def severity_alert(alert_csv_text: str) -> int:
    s = alert_csv_text.strip()
    if not s: return 4
    if s.startswith("❌"): return 2
    rows = [ln for ln in s.splitlines() if ln.strip()]
    if len(rows) <= 1: return 4
    text = "\n".join(rows[1:])
    S1 = ("ORA-00600","ORA-07445")
    if any(code in text for code in S1): return 1
    S2 = ("ORA-04031","ORA-04030","ORA-01652","ORA-01654","ORA-01628","ORA-01578","ORA-01157","ORA-01110")
    if any(code in text for code in S2): return 2
    return 3

def severity_backup(text: str) -> int:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines: return 4
    bad = sum(1 for ln in lines if ln.strip().startswith("❌"))
    if bad >= 3: return 1
    if bad >= 1: return 2
    return 4

# ---------- step runners ----------
def run_config_check(db_dir: Path, out_dir: Path, target_version: str) -> str:
    auto = db_dir / "auto_collection"
    mfec_pm = auto / "mfec_pm.txt"
    buf = io.StringIO()
    if not mfec_pm.exists():
        msg = f"⚠️ Skipped config_check (missing {mfec_pm})\n"
        buf.write(msg); write_file(out_dir / "config_check.txt", buf.getvalue()); return buf.getvalue()
    content = safe_read_text(mfec_pm)
    buf.write(f"File: {mfec_pm}\n")
    if config_check and hasattr(config_check,"check_oracle_config"):
        try:
            _stdout = sys.stdout; sys.stdout = io.StringIO()
            config_check.check_oracle_config(content, target_version)
            result = sys.stdout.getvalue(); sys.stdout = _stdout
            buf.write(result)
        except Exception as e:
            try: sys.stdout = _stdout
            except Exception: pass
            buf.write(f"❌ config_check failed: {e}\n")
    else:
        buf.write("❌ config_check module not importable\n")
    text = buf.getvalue(); write_file(out_dir / "config_check.txt", text); return text

def run_awr(db_dir: Path, out_dir: Path, copy_selected_to: Optional[Path]=None) -> Tuple[Optional[Path], str]:
    report_dir = db_dir / "report"; buf = io.StringIO()
    if not report_dir.exists():
        msg = "⚠️ Skipped AWR (no report folder)\n"; write_file(out_dir / "awr_analysis.txt", msg); return None, msg
    htmls = list(report_dir.glob("*.html"))
    if not htmls:
        msg = "⚠️ Skipped AWR (no *.html)\n"; write_file(out_dir / "awr_analysis.txt", msg); return None, msg

    # Score all AWRs and sort by score descending
    scored_awrs = []
    for h in htmls:
        score_seconds = score_awr(h)
        scored_awrs.append((score_seconds, h))
    scored_awrs.sort(key=lambda x: x[0], reverse=True)

    # Get the top 3 reports or fewer if less than 3 exist
    top_3_awrs = scored_awrs[:3]
    best = top_3_awrs[0][1] if top_3_awrs else None

    # Copy the top 3 AWR HTMLs to target directory with new naming convention
    if copy_selected_to is not None:
        try:
            copy_selected_to.mkdir(parents=True, exist_ok=True)
            for i, (score_seconds, awr_path) in enumerate(top_3_awrs):
                score_minutes = int(score_seconds / 60)
                new_name = f"(top{i+1}_{score_minutes}){awr_path.name}"
                dest = copy_selected_to / new_name
                shutil.copy2(awr_path, dest)
                buf.write(f"Copied AWR (top {i+1}) to: {dest}\n")
        except Exception as e:
            buf.write(f"❌ Failed to copy selected AWRs to {copy_selected_to}: {e}\n")
    
    buf.write("\n")
    
    # Analyze only the top AWR report
    if best:
        buf.write(f"Selected AWR for analysis: {best.name}\n\n")
        if awr_analyzer:
            try:
                data = awr_analyzer.analyze(best)
                _stdout = sys.stdout; sys.stdout = io.StringIO()
                awr_analyzer.print_report(data)
                rendered = sys.stdout.getvalue(); sys.stdout = _stdout
                buf.write(rendered)
            except Exception as e:
                try: sys.stdout = _stdout
                except Exception: pass
                buf.write(f"❌ AWR analyze failed: {e}\n")
        else:
            buf.write("❌ awr_analyzer not importable\n")
    else:
        buf.write("⚠️ No AWR reports to analyze.\n")

    text = buf.getvalue(); write_file(out_dir / "awr_analysis.txt", text); return best, text

def run_tablespace_checks(db_dir: Path, out_dir: Path) -> Tuple[str, List[Tuple[str, str]]]:
    """
    Returns:
      - full_text (for terminal and file)
      - per_file list of (pdb_name, per_file_text) from tablespace_XXX.txt -> 'XXX'
    """
    files = sorted(db_dir.glob("tablespace_*.txt"))
    buf = io.StringIO()
    per_file: List[Tuple[str, str]] = []

    if not files:
        msg = "⚠️ Skipped tablespace (no tablespace_*.txt in DB root)\n"
        write_file(out_dir / "tablespace_report.txt", msg)
        return msg, per_file

    for f in files:
        m = re.match(r"tablespace_(.+?)\.txt$", f.name, re.IGNORECASE)
        pdb_name = m.group(1) if m else db_dir.name

        buf.write(f"[{f.name}]\n")
        if table_space_check and hasattr(table_space_check, "check_tablespace_free_space"):
            try:
                _stdout = sys.stdout
                sys.stdout = io.StringIO()
                table_space_check.check_tablespace_free_space(str(f))
                result = sys.stdout.getvalue()
                sys.stdout = _stdout
                result = result.strip()
                buf.write(result + "\n\n")
                per_file.append((pdb_name, result))
            except Exception as e:
                try: sys.stdout = _stdout
                except Exception: pass
                err = f"❌ tablespace check failed: {e}"
                buf.write(err + "\n\n")
                per_file.append((pdb_name, err))
        else:
            msg = "❌ table_space_check not importable"
            buf.write(msg + "\n\n")
            per_file.append((pdb_name, msg))

    full_text = buf.getvalue()
    write_file(out_dir / "tablespace_report.txt", full_text)
    return full_text, per_file

def run_alert_log(db_dir: Path, out_dir: Path, map_csv: Optional[Path], alert_days: int = 92) -> str:
    """
    Count ONLY entries whose timestamp is within last `alert_days`.
    Normalize tz: naive -> local tz; aware -> convert to local tz.
    """
    log_dir = db_dir / "log"
    if not log_dir.exists():
        msg = "⚠️ Skipped alert log (log folder not found)\n"
        write_file(out_dir / "alert_report.csv", "Alert code,Alert info,first occur,count,cause,action\n")
        return msg

    dbname = db_dir.name
    candidates = list(log_dir.glob(f"alert_{dbname}*.log")) or list(log_dir.glob("alert_*.log"))
    if not candidates:
        msg = "⚠️ Skipped alert log (no alert_*.log found)\n"
        write_file(out_dir / "alert_report.csv", "Alert code,Alert info,first occur,count,cause,action\n")
        return msg

    if not alert_map:
        msg = "❌ alert_log_check_mapped not importable\n"
        write_file(out_dir / "alert_report.csv", "Alert code,Alert info,first occur,count,cause,action\n")
        return msg

    alert_path = candidates[0]
    now_local = datetime.now().astimezone()
    local_tz = now_local.tzinfo
    since_dt = now_local - timedelta(days=alert_days)
    ora_re = re.compile(r"\b(ORA-\d{5})\b[: ]?(.*)")

    agg: Dict[str, Dict[str, Any]] = {}
    current_ts_str: Optional[str] = None
    current_ts_dt: Optional[datetime] = None

    try:
        with alert_path.open("r", encoding="utf-8", errors="replace") as fp:
            for raw in fp:
                line = raw.rstrip("\n")
                ts = parse_ts(line)
                if ts:
                    if ts.tzinfo is None: ts = ts.replace(tzinfo=local_tz)
                    else: ts = ts.astimezone(local_tz)
                    current_ts_dt = ts; current_ts_str = line.strip(); continue
                m = ora_re.search(line)
                if not m: continue
                if current_ts_dt is None or current_ts_dt < since_dt: continue
                code = m.group(1).strip()
                info = (m.group(2) or "").strip()
                meta = agg.setdefault(code, {"first": current_ts_str, "first_dt": current_ts_dt, "info": info, "count": 0})
                meta["count"] += 1
                if current_ts_dt < meta["first_dt"]:
                    meta["first_dt"] = current_ts_dt; meta["first"] = current_ts_str
                    if info: meta["info"] = info

        rows = sorted(agg.items(), key=lambda item: (item[1]['first'] is None, item[1]['first'] or 'ZZZ', item[0]))
        mapping = alert_map.load_mapping(str(map_csv)) if map_csv else {}

        out_csv = out_dir / "alert_report.csv"
        with out_csv.open("w", encoding="utf-8", newline="") as f:
            w = csv.writer(f, lineterminator="\n")
            w.writerow(["Alert code","Alert info","first occur","count","cause","action"])
            for code, meta in rows:
                m_map = mapping.get(code, {})
                w.writerow([
                    code,
                    (meta.get("info") or "").replace("\n"," ").replace("\r"," "),
                    meta.get("first") or "",
                    meta.get("count", 0),
                    m_map.get("cause",""),
                    m_map.get("action",""),
                ])

        header = "Alert code,Alert info,first occur,count,cause,action"
        out_text_lines = [header]
        for code, meta in rows:
            m_map = mapping.get(code, {})
            out_text_lines.append(",".join([
                code,
                (meta.get("info") or "").replace(","," ").replace("\n"," ").replace("\r"," "),
                meta.get("first") or "",
                str(meta.get("count", 0)),
                (m_map.get("cause","") or "").replace(","," "),
                (m_map.get("action","") or "").replace(","," "),
            ]))
        return "\n".join(out_text_lines) + ("\n" if out_text_lines else "")

    except Exception as e:
        msg = f"❌ Alert report failed: {e}\n"
        write_file(out_dir / "alert_report.csv", "Alert code,Alert info,first occur,count,cause,action\n")
        return msg

def run_backups(db_dir: Path, out_dir: Path, days: int = 7) -> str:
    backup_dir = db_dir / "auto_collection" / "backup"; buf = io.StringIO()
    if not backup_dir.exists():
        msg = "⚠️ Skipped backups (auto_collection\\backup not found)\n"
        write_file(out_dir / "backup_report.txt", msg); return msg
    wanted = ["backup_arch.log","backup_con.log","backup_db.log"]
    present = [backup_dir / w for w in wanted if (backup_dir / w).exists()]
    if not present:
        msg = "⚠️ Skipped backups (no backup_*.log found)\n"
        write_file(out_dir / "backup_report.txt", msg); return msg
    if not (backup_check and hasattr(backup_check, "check_file")):
        msg = "❌ backup_check not importable\n"
        write_file(out_dir / "backup_report.txt", msg); return msg
    for p in present:
        try:
            msg = backup_check.check_file(p, days, None); buf.write(msg + "\n")
        except Exception as e:
            buf.write(f"❌ {p.name} failed: {e}\n")
    text = buf.getvalue(); write_file(out_dir / "backup_report.txt", text); return text

# ---------- Excel writer (merged like Book2.xlsx) ----------
def _write_excel(rows: List[Dict[str,str]], out_path: Path):
    import pandas as pd
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Order checklist items to match sheet
    order_priority = {
        "Database Configuration": 0,
        "Database Performance": 1,
        "Database Size and Allocated Growth Rate": 2,
        "Tablespaces Size and Free Space": 3,
        "Database Alert log": 4,
        "Backup Status": 5,
    }
    for r in rows:
        r["_sort_chk"] = order_priority.get(r["Checklist Items"], 9)

    df = pd.DataFrame(rows, columns=["System Name","Database","Checklist Items","Status","Severity","Description","_sort_chk"])
    # IMPORTANT: sort by System (CDB) then Database (PDB) so merges match Book2
    df = df.sort_values(by=["System Name","Database","_sort_chk"], kind="stable").reset_index(drop=True)

    with pd.ExcelWriter(out_path, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="Summary")
        wb  = writer.book
        ws  = writer.sheets["Summary"]

        # Formats
        header_fmt = wb.add_format({"bold": True, "align":"center", "valign":"vcenter", "border":1})
        wrap       = wb.add_format({"text_wrap": True, "valign":"top", "border":1})
        center     = wb.add_format({"align":"center", "valign":"vcenter", "border":1})
        blue_cell  = wb.add_format({"bg_color":"#E7F0FE", "align":"center", "valign":"vcenter", "border":1})
        green      = wb.add_format({"bg_color":"#E6F4EA", "border":1})
        orange     = wb.add_format({"bg_color":"#FFE8CC", "border":1})
        red        = wb.add_format({"bg_color":"#FCE8E8", "border":1})
        yellow     = wb.add_format({"bg_color":"#FFF3BD", "border":1})

        # Column widths
        ws.set_column("A:A", 22)  # System Name (CDB)
        ws.set_column("B:B", 18)  # Database (PDB)
        ws.set_column("C:C", 35)  # Checklist Items
        ws.set_column("D:D", 12)  # Status
        ws.set_column("E:E", 18)  # Severity
        ws.set_column("F:F", 100) # Description

        # Header style
        for col, name in enumerate(["System Name","Database","Checklist Items","Status","Severity","Description","_sort_chk"]):
            if name == "_sort_chk": continue
            ws.write(0, col, name, header_fmt)

        # Paint Status/Severity + wrap Description
        for r in range(len(df)):
            sev_text = str(df.iloc[r]["Severity"])
            if   sev_text.startswith("Severity 1"): sev_fmt = red;    st_fmt = red
            elif sev_text.startswith("Severity 2"): sev_fmt = orange; st_fmt = orange
            elif sev_text.startswith("Severity 3"): sev_fmt = yellow; st_fmt = yellow
            else:                                   sev_fmt = green;  st_fmt = green
            ws.write(r+1, 3, df.iloc[r]["Status"], st_fmt)
            ws.write(r+1, 4, df.iloc[r]["Severity"], sev_fmt)
            ws.write(r+1, 5, df.iloc[r]["Description"], wrap)

        # Merge System (A) and Database (B)
        n = len(df)
        def merge_range_if_needed(r1, r2, col, text):
            if r2 > r1:
                ws.merge_range(r1+1, col, r2+1, col, text, blue_cell)
            else:
                ws.write(r1+1, col, text, blue_cell)

        # Merge by System Name (CDB)
        s = 0
        while s < n:
            sys_cdb = df.loc[s, "System Name"]
            e = s
            while e+1 < n and df.loc[e+1, "System Name"] == sys_cdb:
                e += 1
            merge_range_if_needed(s, e, 0, sys_cdb)

            # Within system block, merge PDB names
            j = s
            while j <= e:
                pdb = df.loc[j, "Database"]
                k = j
                while k+1 <= e and df.loc[k+1, "Database"] == pdb:
                    k += 1
                merge_range_if_needed(j, k, 1, pdb if pdb else "")
                j = k + 1

            s = e + 1

        # Center checklist items
        for r in range(len(df)):
            ws.write(r+1, 2, df.iloc[r]["Checklist Items"], center)

        ws.set_column("G:G", None, None, {'hidden': True})

# ------------- Orchestrate -------------
def run_all(input_path: Path, map_csv: Optional[Path], target_version: str, report_root: Path, alert_days: int) -> None:
    # We still show the top label in console/summary, but Excel 'System Name' = CDB folder
    if is_zip(input_path):
        print(f"→ Extracting zip: {input_path}")
        source_root = extract_zip(input_path)
        top_label = Path(input_path).stem
    else:
        source_root = input_path
        top_label = Path(input_path).name

    first_level = find_first_level_used(source_root)
    db_dirs = list_database_dirs(first_level)
    if not db_dirs:
        print("No database folders found (need subfolders with auto_collection/report/log).")
        return

    report_root.mkdir(parents=True, exist_ok=True)
    summary_lines: List[str] = []
    excel_rows: List[Dict[str,str]] = []

    summary_lines.append("# PM Summary\n")
    summary_lines.append(f"- Source: `{input_path}`")
    summary_lines.append(f"- First level used: `{first_level}`")
    summary_lines.append(f"- Databases found: {', '.join([d.name for d in db_dirs])}\n")

    for db in db_dirs:
        cdb_name = db.name  # ←← Excel "System Name" should be the CDB folder name
        print("\n" + "="*80)
        print(f"DB: {cdb_name}")
        print("="*80)
        out_dir = report_root / cdb_name
        out_dir.mkdir(parents=True, exist_ok=True)

        # 2.1 CONFIG (CDB-wide)
        print("\n--- CONFIG CHECK ---")
        cfg_text = run_config_check(db, out_dir, target_version)
        print(cfg_text, end="")
        cfg_sev = severity_config(cfg_text)

        # 2.2 AWR (CDB-wide)
        print("\n--- AWR ANALYSIS ---")
        awr_selected, awr_text = run_awr(db, out_dir, copy_selected_to=out_dir)
        print(awr_text, end="")
        awr_sev = severity_awr(awr_text)

        # 2.3 TABLESPACE (per PDB)
        print("\n--- TABLESPACE CHECK ---")
        ts_text, ts_items = run_tablespace_checks(db, out_dir)
        print(ts_text, end="")

        # 2.4 ALERT (CDB-wide)
        print(f"\n--- ALERT LOG (last {alert_days} days) ---")
        alert_csv_or_msg = run_alert_log(db, out_dir, map_csv, alert_days=alert_days)
        print(alert_csv_or_msg, end="" if alert_csv_or_msg.endswith("\n") else "\n")
        a_sev = severity_alert(alert_csv_or_msg)

        # 2.5 BACKUP (CDB-wide)
        print("\n--- BACKUP CHECK ---")
        backup_text = run_backups(db, out_dir)
        print(backup_text, end="")
        b_sev = severity_backup(backup_text)

        # ===== Build Excel rows exactly like Book2.xlsx =====
        pdb_rows = ts_items if ts_items else [(cdb_name, "No tablespace files")]

        for pdb_name, ts_item_text in pdb_rows:
            ts_sev = severity_tablespace(ts_item_text)

            # Configuration
            excel_rows.append({
                "System Name": cdb_name,           # CDB folder
                "Database": pdb_name,              # PDB from tablespace_XXX.txt
                "Checklist Items": "Database Configuration",
                "Status": _status_from_sev(cfg_sev),
                "Severity": _sev_label(cfg_sev),
                "Description": _desc_lines_from(cfg_text),
            })
            # Performance
            excel_rows.append({
                "System Name": cdb_name,
                "Database": pdb_name,
                "Checklist Items": "Database Performance",
                "Status": _status_from_sev(awr_sev),
                "Severity": _sev_label(awr_sev),
                "Description": _desc_lines_from(awr_text),
            })
            # Size/Growth (placeholder)
            excel_rows.append({
                "System Name": cdb_name,
                "Database": pdb_name,
                "Checklist Items": "Database Size and Allocated Growth Rate",
                "Status": "Normal",
                "Severity": _sev_label(4),
                "Description": "",
            })
            # Tablespaces (per PDB)
            excel_rows.append({
                "System Name": cdb_name,
                "Database": pdb_name,
                "Checklist Items": "Tablespaces Size and Free Space",
                "Status": _status_from_sev(ts_sev),
                "Severity": _sev_label(ts_sev),
                "Description": _desc_lines_from(ts_item_text),
            })
            # Alerts (CDB result repeated per PDB for layout)
            excel_rows.append({
                "System Name": cdb_name,
                "Database": pdb_name,
                "Checklist Items": "Database Alert log",
                "Status": _status_from_sev(a_sev),
                "Severity": _sev_label(a_sev),
                "Description": _desc_lines_from(alert_csv_or_msg, max_lines=8) if a_sev < 4 else "No ORA-* in the last window.",
            })
            # Backups (CDB result repeated per PDB)
            excel_rows.append({
                "System Name": cdb_name,
                "Database": pdb_name,
                "Checklist Items": "Backup Status",
                "Status": _status_from_sev(b_sev),
                "Severity": _sev_label(b_sev),
                "Description": _desc_lines_from(backup_text),
            })

        # Text summary
        summary_lines.append(f"## {cdb_name}\n")
        if awr_selected:
            summary_lines.append(f"- AWR chosen: `{Path(awr_selected).name}`")
        summary_lines.append(f"- Reports: `{out_dir}`\n")

    write_file(report_root / "summary_report.md", "\n".join(summary_lines))
    _write_excel(excel_rows, report_root / "pm_summary.xlsx")

    print("\n" + "="*80)
    print(f"SUMMARY: {report_root / 'summary_report.md'}")
    print(f"EXCEL  : {report_root / 'pm_summary.xlsx'}")
    print("="*80)

def main():
    ap = argparse.ArgumentParser(description="Run PM workflow, print all, save under mini_pm_report and build Excel summary (Book2 layout).")
    ap.add_argument("input", help="Zip file OR extracted folder (e.g., ...\\PM_node1_week2)")
    ap.add_argument("--map", help="Path to ora_code_table.csv", default=None)
    ap.add_argument("--target-version", default="19.27", help="Target Oracle RU (e.g., 19.27)")
    ap.add_argument("--out", default="mini_pm_report", help="Output root folder (default: mini_pm_report)")
    ap.add_argument("--alert-days", type=int, default=92, help="Only include alert entries for the last N days (default ~3 months)")
    args = ap.parse_args()

    input_path = Path(args.input)
    if not input_path.exists(): raise SystemExit(f"Not found: {input_path}")
    map_csv = Path(args.map) if args.map else None
    if map_csv and not map_csv.exists():
        print(f"⚠️ Mapping CSV not found: {map_csv} (will omit cause/action)")
        map_csv = None
    report_root = Path(args.out) if Path(args.out).is_absolute() else Path.cwd() / args.out
    run_all(input_path, map_csv, args.target_version, report_root, alert_days=args.alert_days)

if __name__ == "__main__":
    main()