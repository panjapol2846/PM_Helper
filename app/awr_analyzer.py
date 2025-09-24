#!/usr/bin/env python3
"""
AWR Parser (targeted tables only)

Extracts and prints:
  1) Instance Efficiency Percentages (Target 100%)
  2) Top 10 Foreground Events by Total Wait Time
  3) SQL ordered by Elapsed Time
  4) PGA Memory Advisory
  5) SGA Target Advisory
"""

import argparse
import re
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
from bs4 import BeautifulSoup, NavigableString, Tag



# ---------- helpers ----------

def _read_html(path: Path) -> BeautifulSoup:
    html = path.read_text(encoding="utf-8", errors="ignore")
    return BeautifulSoup(html, "html.parser")

def _clean_cols(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    if isinstance(df.columns, pd.MultiIndex):
        df.columns = df.columns.map(" ".join)
    df.columns = [str(c).replace("\xa0", " ").strip() for c in df.columns]
    # de-dup column names to avoid pandas dropping duplicates
    seen = {}
    new_cols = []
    for c in df.columns:
        if c in seen:
            seen[c] += 1
            new_cols.append(f"{c}.{seen[c]}")
        else:
            seen[c] = 0
            new_cols.append(c)
    df.columns = new_cols
    return df

_num_pat = re.compile(r"([-+]?\d*\.?\d+(?:[eE][-+]?\d+)?)")

def _num(x: Any) -> Optional[float]:
    if x is None:
        return None
    s = str(x).replace(",", "").replace("%", "").strip()
    m = _num_pat.search(s)
    return float(m.group(1)) if m else None

def _contains_any(text: str, needles: List[str]) -> bool:
    t = text.lower()
    return any(n.lower() in t for n in needles)

def _table_to_df(table: Tag) -> Optional[pd.DataFrame]:
    try:
        return pd.read_html(StringIO(str(table)), flavor="lxml")[0]
    except Exception:
        try:
            return pd.read_html(StringIO(str(table)))[0]
        except Exception:
            return None

def _find_table_by_summary(soup: BeautifulSoup, summary_patterns: List[str]) -> Optional[pd.DataFrame]:
    for tbl in soup.find_all("table"):
        summary = (tbl.get("summary") or "").lower()
        if any(re.search(pat, summary) for pat in summary_patterns):
            df = _table_to_df(tbl)
            if df is not None and not df.empty:
                return _clean_cols(df)
    return None

def _find_table_by_title_then_next_table(soup: BeautifulSoup, title_patterns: List[str]) -> Optional[pd.DataFrame]:
    # match anywhere in the document (text or tag)
    def text_matches(node) -> bool:
        try:
            return isinstance(node, (Tag, NavigableString)) and _contains_any(str(node), title_patterns)
        except Exception:
            return False

    anchor = soup.find(text_matches)
    if not anchor:
        return None
    start = anchor if isinstance(anchor, Tag) else (anchor.parent if hasattr(anchor, "parent") else None)
    if not start:
        return None

    nxt = start.find_next("table")
    if not nxt:
        return None
    df = _table_to_df(nxt)
    return _clean_cols(df) if df is not None and not df.empty else None

def get_db_time_from_html(soup: BeautifulSoup) -> float:
    """Extracts DB Time in minutes from the AWR report header."""
    header_text = soup.get_text()
    _DB_TIME_INLINE = re.compile(r"DB\s*Time[:\s]*([\d,\.]+)\s*(hours?|hrs?|h|minutes?|mins?|m|seconds?|secs?|s)?", re.I)
    m = _DB_TIME_INLINE.search(header_text)
    if m:
        val = float(str(m.group(1)).replace(",", ""))
        unit = (m.group(2) or "").lower()
        if unit.startswith("h"): return val * 60.0
        if unit.startswith("s"): return val / 60.0
        return val
    return 0.0

# ---------- section parsers ----------

def parse_instance_efficiency(soup: BeautifulSoup) -> Dict[str, Optional[float]]:
    # Prefer table summary (reliable in your file)
    df = _find_table_by_summary(
        soup,
        [r"instance\s+efficiency\s+percentages"]  # case-insensitive regex
    )
    # Fallback: title then next table
    if df is None:
        df = _find_table_by_title_then_next_table(
            soup,
            ["Instance Efficiency Percentages"]
        )
    if df is None or df.empty:
        return {}

    # This table is usually 2 metrics per row: metric:value metric:value
    out: Dict[str, Optional[float]] = {}
    for _, row in df.iterrows():
        values = [str(v).strip() for v in row.values]
        # walk pairs
        for i in range(0, len(values), 2):
            try:
                metric = values[i]
                val = values[i + 1] if i + 1 < len(values) else None
            except Exception:
                continue
            if not metric or ":" not in metric:
                # some AWRs omit the colon in headers; tolerate both
                pass
            # keep only rows that look like percentages we care about
            if _contains_any(metric, ["Hit %", "Parse", "Latch", "Redo", "Buffer", "Library", "Flash Cache"]):
                out[metric.replace(":", "")] = _num(val)
    return out

def parse_top10_foreground_events(soup: BeautifulSoup) -> List[Dict[str, Any]]:
    df = _find_table_by_summary(
        soup,
        [r"top\s+10.*wait\s+events.*total\s+wait\s+time"]
    )
    if df is None:
        df = _find_table_by_title_then_next_table(
            soup, ["Top 10 Foreground Events by Total Wait Time"]
        )
    if df is None or df.empty:
        return []

    df = _clean_cols(df)
    # rename common columns
    ren = {}
    for c in df.columns:
        lc = c.lower()
        if "event" in lc and "class" not in lc:
            ren[c] = "event"
        elif "waits" in lc:
            ren[c] = "waits"
        elif "total wait" in lc or ("time" in lc and "(sec" in lc):
            ren[c] = "total_wait_time_s"
        elif "avg wait" in lc:
            ren[c] = "avg_wait"
        elif "% db time" in lc:
            ren[c] = "pct_db_time"
        elif "wait class" in lc:
            ren[c] = "wait_class"
    df = df.rename(columns=ren)
    keep = [c for c in ["event", "waits", "total_wait_time_s", "avg_wait", "pct_db_time", "wait_class"] if c in df.columns]

    # numeric conversions
    for c in ["waits", "total_wait_time_s", "pct_db_time"]:
        if c in df.columns:
            df[c] = df[c].map(_num)

    return df[keep].head(10).to_dict(orient="records")

def parse_sql_ordered_by_elapsed(soup: BeautifulSoup) -> List[Dict[str, Any]]:
    """
    Find and return only the 'SQL ordered by Elapsed Time' rows (top 10).
    Strategy: read all tables -> pick those that look like the Elapsed Time SQL table
    (must contain SQL ID + Elapsed Time columns), handle duplicate headers, clean numbers.
    """
    from io import StringIO

    # Read ALL tables once (avoids title/anchor brittleness)
    try:
        dfs = pd.read_html(StringIO(str(soup)), flavor="lxml")
    except Exception:
        try:
            dfs = pd.read_html(StringIO(str(soup)))
        except Exception:
            return []

    def _has_anycell(df: pd.DataFrame, needles: List[str]) -> bool:
        # headers
        for col in df.columns:
            if _contains_any(str(col), needles):
                return True
        # a few stringy cells
        for _, row in df.head(20).iterrows():
            for v in row.values:
                if isinstance(v, str) and _contains_any(v, needles):
                    return True
        return False

    wanted = []
    for df in dfs:
        df = _clean_cols(df)
        # quick filter: must look like the "Elapsed Time" SQL table
        if not _has_anycell(df, ["sql id", "sqlid", "sql_id"]):
            continue
        if not _has_anycell(df, ["elapsed time"]):  # focus ONLY elapsed-time table
            continue

        # De-dup duplicate column names so pandas doesn't drop them
        seen, new_cols = {}, []
        for c in df.columns:
            c = str(c).strip()
            if c in seen:
                seen[c] += 1
                new_cols.append(f"{c}.{seen[c]}")
            else:
                seen[c] = 0
                new_cols.append(c)
        cdf = df.copy()
        cdf.columns = new_cols

        # Normalize/rename columns we care about
        rename_map = {}
        for c in cdf.columns:
            lc = re.sub(r"\s+", " ", str(c)).strip().lower()
            if "sql id" in lc or lc == "sqlid" or "sql_id" in lc:
                rename_map[c] = "sql_id"
            elif ("elapsed time" in lc and "/exec" in lc) or "elapsed time per exec" in lc:
                rename_map[c] = "elapsed_per_exec_s"
            elif ("elapsed time" in lc) and ("(s" in lc or "sec" in lc or "time (s)" in lc):
                rename_map[c] = "elapsed_time_s"
            elif "executions" in lc:
                rename_map[c] = "executions"
            elif "%total" in lc and "elapsed" in lc:
                rename_map[c] = "pct_total_elapsed"

        cdf = cdf.rename(columns=rename_map)

        # Require sql_id and some elapsed time signal
        if "sql_id" not in cdf.columns:
            continue
        if not (("elapsed_time_s" in cdf.columns) or ("elapsed_per_exec_s" in cdf.columns)):
            continue

        keep = [c for c in ["sql_id", "elapsed_time_s", "executions", "elapsed_per_exec_s", "pct_total_elapsed"]
                if c in cdf.columns]
        trimmed = cdf[keep].head(10).copy()

        # Numeric cleanup
        for col in trimmed.columns:
            if col != "sql_id":
                trimmed[col] = trimmed[col].map(_num)

        wanted.append(trimmed)

    if not wanted:
        return []

    out = pd.concat(wanted, ignore_index=True)
    # drop duplicates by sql_id (keep first)
    if "sql_id" in out.columns:
        out = out.drop_duplicates(subset=["sql_id"], keep="first")

    return out.to_dict(orient="records")


def parse_pga_memory_advisory(soup: BeautifulSoup) -> List[Dict[str, Any]]:
    """
    Return the FULL 'PGA Memory Advisory' / 'PGA Aggregate Target Advisory' table.
    Keeps every column exactly as shown in the AWR (after header cleaning + de-dupe).
    """
    df = _find_table_by_summary(soup, [r"pga.*advisory"])
    if df is None:
        df = _find_table_by_title_then_next_table(
            soup, ["PGA Memory Advisory", "PGA Aggregate Target Advisory"]
        )
    if df is None or df.empty:
        return []
    df = _clean_cols(df)
    # Return every column untouched (numeric conversion skipped to preserve raw values/units)
    return df.to_dict(orient="records")


def parse_sga_target_advisory(soup: BeautifulSoup) -> List[Dict[str, Any]]:
    """
    Return the FULL 'SGA Target Advisory' table.
    Keeps every column exactly as shown in the AWR (after header cleaning + de-dupe).
    """
    df = _find_table_by_summary(soup, [r"sga.*target.*advisory"])
    if df is None:
        df = _find_table_by_title_then_next_table(soup, ["SGA Target Advisory"])
    if df is None or df.empty:
        return []
    df = _clean_cols(df)
    # Return every column untouched (numeric conversion skipped to preserve raw values/units)
    return df.to_dict(orient="records")

def parse_instance_thread_activity(soup: BeautifulSoup) -> List[Dict[str, Any]]:
    """
    Parse 'Instance Activity Stats - Thread Activity' (Statistic | Total | per Hour).
    Returns the full table as a list of dicts.
    """
    # Prefer the table's summary attribute (most reliable)
    df = _find_table_by_summary(
        soup,
        [r"thread\s+activity\s+stats"]  # matches: "This table displays thread activity stats..."
    )
    # Fallback: match the section title then grab the next table
    if df is None:
        df = _find_table_by_title_then_next_table(
            soup, ["Instance Activity Stats - Thread Activity"]
        )

    if df is None or df.empty:
        return []

    df = _clean_cols(df)  # de-dup/normalize headers
    # Keep columns as-is so you see exactly what AWR shows
    return df.to_dict(orient="records")


def analyze_instance_efficiency(data: Dict[str, Optional[float]]) -> str:
    warnings = []
    for metric, value in data.items():
        if "Flash Cache Hit" in metric:
            continue
        if "Hit %" in metric and value is not None and value < 70:
            warnings.append(f"{metric}: {value:.2f}")
        elif "Parse" in metric and "to" in metric and value is not None and value < 70:
            warnings.append(f"{metric}: {value:.2f}")
        elif "Latch Hit %" in metric and value is not None and value < 70:
            warnings.append(f"{metric}: {value:.2f}")
    if warnings:
        return f"❌ Hit Ratio: {', '.join(warnings)}"
    else:
        return "✅ Hit Ratio: All statistics more than 70% or follow the same trend"

def analyze_top10_foreground_events(data: List[Dict[str, Any]], db_time_minutes: float) -> str:
    # If DB Time is less than 50 minutes, the report is considered "Normal" for this check
    if db_time_minutes < 50:
        return "✅ Wait event: No concerning wait event with significant DB time more than CPU timeng running SQL with significant running time or wait"

    # Find DB CPU %
    db_cpu_time = 0
    for row in data:
        if row.get("event") == "DB CPU":
            db_cpu_time = row.get("pct_db_time", 0)
            break
    
    warnings = []
    for row in data:
        event = row.get("event")
        pct_db_time = row.get("pct_db_time")
        if event != "DB CPU" and pct_db_time is not None and pct_db_time > db_cpu_time:
            warnings.append(f"{event}: {pct_db_time:.1f}% DB Time")
    
    if warnings:
        return f"❌ {', '.join(warnings)}"
    else:
        return "✅ Wait event: No concerning wait event with significant DB time more than CPU timeng running SQL with significant running time or wait"

def analyze_sql_ordered_by_elapsed(data: List[Dict[str, Any]]) -> str:
    warnings = []
    for row in data:
        sql_id = row.get("sql_id")
        if not sql_id or sql_id in warnings:
            continue

        # Use .get(key, 0) or 0 to safely handle None values after parsing
        elapsed_time = row.get("elapsed_time_s", 0) or 0
        elapsed_per_exec = row.get("elapsed_per_exec_s", 0) or 0
        executions = row.get("executions", 0) or 0

        # Condition 1: Total elapsed time is very high
        cond1 = elapsed_time > 100000

        # Condition 2: Elapsed time per execution is very high
        cond2 = elapsed_per_exec > 3000

        # Condition 3: Frequent execution with high time per execution
        cond3 = (executions > 100 and elapsed_per_exec > 300)

        if cond1 or cond2 or cond3:
            warnings.append(sql_id)

    if warnings:
        # Filter out any potential None values that might have slipped through
        valid_warnings = [str(w) for w in warnings if w]
        if valid_warnings:
            sql_ids = ','.join(valid_warnings)
            return f"❌Concerning running SQL with significant running time or wait  sql_id:{sql_ids}"

    return "✅ Top Running SQL: There is no concerning running SQL with significant running time or wait"


def analyze_sga_advisory(data: List[Dict[str, Any]]) -> str:
    """
    Analyzes SGA Target Advisory data to recommend size changes.

    A recommendation is triggered if either of these conditions are met for a future size:
    1. Original Logic: The relative improvement in physical reads is significant compared to the SGA size increase.
    2. New Logic: A small SGA increase (<1GB) results in a very large drop (>10M) in physical reads.
    """
    current_row = None
    target_row = None

    # First, find the current configuration row (Size Factor = 1.0)
    for row in data:
        if _num(row.get('SGA Size Factor')) == 1.00:
            current_row = row
            break
    
    if not current_row:
        return "✅ SGA Advisor: Appropriate DB time and physical read"

    # Now, iterate through potential target rows (size factor > 1.0) to find the first suitable recommendation
    for row in data:
        size_factor = _num(row.get('SGA Size Factor'))
        
        # We only care about rows representing an increase in size
        if size_factor is None or size_factor <= 1.00:
            continue

        # Extract numeric values needed for both conditions
        current_physical_reads = _num(current_row.get('Est Physical Reads'))
        est_physical_reads = _num(row.get('Est Physical Reads'))
        current_sga_size = _num(current_row.get('SGA Target Size (M)'))
        target_sga_size = _num(row.get('SGA Target Size (M)'))

        # If data is missing for a row, skip it
        if any(v is None for v in [current_physical_reads, est_physical_reads, current_sga_size, target_sga_size]):
            continue

        # --- Condition 1: Original proportional improvement logic ---
        condition1_met = False
        # Avoid division by zero if there are no physical reads currently
        if current_physical_reads > 0:
            physical_reads_improvement_pct = (current_physical_reads - est_physical_reads) / current_physical_reads
            required_improvement_pct = 1.5 * (size_factor - 1.0)
            if physical_reads_improvement_pct >= required_improvement_pct:
                condition1_met = True
        
        # --- Condition 2: New logic for large gains from small increases ---
        sga_increase_mb = target_sga_size - current_sga_size
        reads_decrease = current_physical_reads - est_physical_reads
        
        condition2_met = (sga_increase_mb < 1024 and reads_decrease > 10_000_000)

        # If either condition is met, we've found our recommendation.
        # We break to select the smallest SGA increase that satisfies the criteria.
        if condition1_met or condition2_met:
            target_row = row
            break
    
    # If a target row was identified, format the recommendation string
    if target_row:
        # Re-read values to ensure they are the correct ones from the final target_row
        current_sga_size = _num(current_row.get('SGA Target Size (M)'))
        target_sga_size = _num(target_row.get('SGA Target Size (M)'))
        old_reads = _num(current_row.get('Est Physical Reads'))
        new_reads = _num(target_row.get('Est Physical Reads'))
        
        # Final safety check on numbers before formatting output
        if any(v is None for v in [current_sga_size, target_sga_size, old_reads, new_reads]):
             return "✅ SGA Advisor: Appropriate DB time and physical read"
        
        read_diff = old_reads - new_reads
        
        return (f"❌Recommend to increase size from {current_sga_size:.0f} MB to {target_sga_size:.0f} MB. "
                f"Physical Reads would decrease by {read_diff:,.0f} from {old_reads:,.0f} to {new_reads:,.0f}")
    else:
        # If no suitable target row was found after checking all options
        return "✅ SGA Advisor: Appropriate DB time and physical read"


def analyze_pga_advisory(data: List[Dict[str, Any]]) -> str:
    current_row = None
    target_row = None
    for row in data:
        if _num(row.get('Size Factr')) == 1.00:
            current_row = row
        size_factor = _num(row.get('Size Factr'))
        if size_factor is not None and size_factor > 1.00:
            est_extra_mb = _num(row.get('Estd Extra W/A MB Read/ Written to Disk'))
            if current_row and est_extra_mb is not None:
                current_extra_mb = _num(current_row.get('Estd Extra W/A MB Read/ Written to Disk'))
                improvement_ratio = 1.5 * (size_factor - 1.0)
                improvement = current_extra_mb * improvement_ratio

                # Ensure improvement is not zero unless it is valid
                if improvement > 0 and (current_extra_mb - est_extra_mb) >= improvement:
                    target_row = row
                    break

    if not current_row:
        return "✅ PGA Advisor: Appropriate DB time and physical read"
        
    if target_row:
        current_pga_size = _num(current_row.get('PGA Target Est (MB)'))
        target_pga_size = _num(target_row.get('PGA Target Est (MB)'))
        old_rw = _num(current_row.get('Estd Extra W/A MB Read/ Written to Disk'))
        new_rw = _num(target_row.get('Estd Extra W/A MB Read/ Written to Disk'))
        rw_diff = old_rw - new_rw
        
        return (f"❌ PGA Advisor: Recommend to increase size from {current_pga_size:.0f} MB to {target_pga_size:.0f} MB. "
                f"Extra W/A MB Read/Written to Disk would decrease by {rw_diff:,.0f} from {old_rw:,.0f} to {new_rw:,.0f}")
    else:
        return "✅ PGA Advisor: Appropriate DB time and physical read"



def analyze_thread_activity(data: List[Dict[str, Any]]) -> str:
    for row in data:
        if "log switches" in row.get("Statistic", "").lower():
            per_hour = _num(row.get("per Hour"))
            if per_hour is not None and per_hour > 4:
                return f"❌ Redo Log switch: Redo log switch more than 4 times per hour"
    return "✅ Redo Log switch: Redo log switches are within normal range"


# ---------- orchestration & printing ----------

def analyze(html_path: Path) -> Dict[str, Any]:
    soup = _read_html(html_path)
    db_time_minutes = get_db_time_from_html(soup)
    return {
        "DB Time (minutes)": db_time_minutes,
        "Instance Efficiency Percentages (Target 100%)": parse_instance_efficiency(soup),
        "Top 10 Foreground Events by Total Wait Time":   parse_top10_foreground_events(soup),
        "SQL ordered by Elapsed Time":                   parse_sql_ordered_by_elapsed(soup),
        "PGA Memory Advisory":                           parse_pga_memory_advisory(soup),
        "SGA Target Advisory":                           parse_sga_target_advisory(soup),
        "Instance Activity Stats - Thread Activity":     parse_instance_thread_activity(soup),
    }

def print_report(data: Dict[str, Any]) -> None:
    print("\n--- AWR Targeted Tables ---\n")
    print(f"DB Time (minutes): {data.get('DB Time (minutes)', 'N/A'):.2f}\n")
    sep = "\n" + "="*70 + "\n"
    
    # Instance Efficiency
    print("## Instance Efficiency Percentages (Target 100%)\n")
    if not data["Instance Efficiency Percentages (Target 100%)"]:
        print("   (Table not found or empty)")
    else:
        print(analyze_instance_efficiency(data["Instance Efficiency Percentages (Target 100%)"]))
    print(sep)
    
    # Top 10 Foreground Events
    print("## Top 10 Foreground Events by Total Wait Time\n")
    if not data["Top 10 Foreground Events by Total Wait Time"]:
        print("   (Table not found or empty)")
    else:
        print(analyze_top10_foreground_events(data["Top 10 Foreground Events by Total Wait Time"], data["DB Time (minutes)"]))
    print(sep)
    
    # SQL ordered by Elapsed Time
    print("## SQL ordered by Elapsed Time\n")
    if not data["SQL ordered by Elapsed Time"]:
        print("   (Table not found or empty)")
    else:
        print(analyze_sql_ordered_by_elapsed(data["SQL ordered by Elapsed Time"]))
    print(sep)
    
    # SGA Target Advisory
    print("## SGA Target Advisory\n")
    if not data["SGA Target Advisory"]:
        print("   (Table not found or empty)")
    else:
        print(analyze_sga_advisory(data["SGA Target Advisory"]))
    print(sep)

    # PGA Memory Advisory
    print("## PGA Memory Advisory\n")
    if not data["PGA Memory Advisory"]:
        print("   (Table not found or empty)")
    else:
        print(analyze_pga_advisory(data["PGA Memory Advisory"]))
    print(sep)

    # Instance Activity Stats - Thread Activity
    print("## Instance Activity Stats - Thread Activity\n")
    if not data["Instance Activity Stats - Thread Activity"]:
        print("   (Table not found or empty)")
    else:
        print(analyze_thread_activity(data["Instance Activity Stats - Thread Activity"]))
    print(sep)


def main():
    ap = argparse.ArgumentParser(description="Parse selected tables from an Oracle AWR HTML report.")
    ap.add_argument("html_path", type=str, help="Path to AWR HTML report")
    args = ap.parse_args()

    path = Path(args.html_path)
    if not path.exists():
        raise SystemExit(f"File not found: {path}")

    data = analyze(path)
    print_report(data)

if __name__ == "__main__":
    main()