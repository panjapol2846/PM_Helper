#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
config_check.py

Exports:
    check_oracle_config(file_content: str, target_version_str: str) -> None
        Prints:
          - "Checking configuration against target version: ..."
          - Patches line (Up to date / Recommend applying ...)
          - Control file redundancy line
          - Redo logs redundancy line

Notes:
- Version comparison uses only the numeric major.minor (e.g., 19.27 from "19.27 (APR 2025)").
- Control file redundancy = at least 2 unique CONTROLFILE paths found (in the Controlfile
  section or Database Parameter section).
- Redo redundancy (NEW RULE) = number of distinct log groups > 1 (members per group not required).
"""

import re
from typing import Optional, Tuple, Set

# ----------------------------
# Section helpers
# ----------------------------

def _extract_section(content: str, title_regex: str) -> Optional[str]:
    # Capture the block after a ^o^----TITLE----^o^ line until the next section marker
    pat = re.compile(
        r"\^o\^[-]*" + title_regex + r"[-]*\^o\^(.*?)(?=(?:\n\*8\*|>O<|$))",
        re.DOTALL
    )
    m = pat.search(content)
    return m.group(1) if m else None

# ----------------------------
# Version helpers
# ----------------------------

def _extract_file_version(content: str) -> Optional[str]:
    """
    Returns a dotted numeric string from the report like '19.19.0.0.0',
    looking for 'Version' first, then 'Release'.
    """
    m = re.search(r"\bVersion\s+(\d+(?:\.\d+){1,4})", content, flags=re.I)
    if not m:
        m = re.search(r"\bRelease\s+(\d+(?:\.\d+){1,4})", content, flags=re.I)
    return m.group(1) if m else None

def _major_minor_tuple_from_str(num_str: str) -> Tuple[int, int]:
    parts = [int(x) for x in num_str.split(".") if re.fullmatch(r"\d+", x)]
    if len(parts) == 1:
        parts.append(0)
    return (parts[0], parts[1])

def _parse_target_version_input(s: Optional[str]) -> Tuple[Optional[Tuple[int,int]], Optional[str], Optional[str]]:
    """
    Returns (target_mm_tuple, target_mm_str, target_display_string).
    Extracts only digits/dots (e.g. '19.27' from '19.27 (APR 2025)').
    """
    if not s:
        return None, None, None
    m = re.search(r"(\d+(?:\.\d+)*)", s)
    if not m:
        return None, None, s
    numeric = m.group(1)
    return _major_minor_tuple_from_str(numeric), numeric, s

# ----------------------------
# Controlfile redundancy
# ----------------------------

def _controlfile_paths_from_control_section(content: str) -> Set[str]:
    sec = _extract_section(content, r"Controlfile")
    if not sec:
        return set()
    return {p.strip() for p in re.findall(r"(\+\S+/CONTROLFILE/\S+)", sec)}

def _controlfile_paths_fallback(content: str) -> Set[str]:
    """
    Also scan anywhere (e.g., in 'Database Parameter' section) and
    reconstruct wrapped lines by removing internal whitespace.
    """
    matches = re.findall(r"(\+\S+/CONTROLFILE/\S+(?:\s+\S+)*)", content)
    cleaned = {re.sub(r"\s+", "", m) for m in matches}
    return {p for p in cleaned if "/CONTROLFILE/" in p}

def _check_controlfile_redundancy(content: str) -> str:
    paths = _controlfile_paths_from_control_section(content)
    if not paths:
        paths = _controlfile_paths_fallback(content)

    if len(paths) >= 2:
        return "✅ Control file: Redundancy"
    elif len(paths) == 1:
        return "❌ Control file: non Redundancy"
    else:
        return "❌ Control file: section not found"

# ----------------------------
# Redo redundancy (NEW RULE)
# ----------------------------

def _redo_groups_count(content: str) -> int:
    """
    Count distinct GROUP#.
    Prefer 'Amount of log group' section; if missing, parse 'Redo log file'.
    """
    # Try the quick, explicit section first
    sec = _extract_section(content, r"Amount of log group")
    if sec:
        m = re.search(r"COUNT\(DISTINCTGROUP#\)\s+[-\s]+\s*(\d+)", sec)
        if m:
            return int(m.group(1))

    # Fallback: parse the Redo log file table
    sec = _extract_section(content, r"Redo log file")
    groups = set()
    if sec:
        for line in sec.splitlines():
            m = re.match(r"\s*(\d+)\s+\+\S+/ONLINELOG/\S+", line)
            if m:
                groups.add(int(m.group(1)))

    if groups:
        return len(groups)

    # Last chance: scan anywhere in the file
    groups = set(int(g) for g in re.findall(r"^\s*(\d+)\s+\+\S+/ONLINELOG/\S+", content, flags=re.M))
    return len(groups)

def _check_redo_redundancy(content: str) -> str:
    """
    Your rule: MULTIPLE groups (>1) => 'Redundancy', regardless of members per group.
    """
    cnt = _redo_groups_count(content)
    if cnt > 1:
        return "✅ Redo Logs: Redundancy"
    elif cnt == 1:
        return "❌ Redo Logs: non Redundancy"
    else:
        return "❌ Redo Logs: section not found"

# ----------------------------
# Public API (used by pm_runner.py)
# ----------------------------

def check_oracle_config(file_content: str, target_version_str: str) -> None:
    # Version / patches
    print(f"Checking configuration against target version: {target_version_str}")
    file_ver_full = _extract_file_version(file_content)
    target_mm_tuple, _target_mm_str, target_display = _parse_target_version_input(target_version_str)

    if file_ver_full and target_mm_tuple:
        file_mm_tuple = _major_minor_tuple_from_str(file_ver_full)
        if file_mm_tuple == target_mm_tuple:
            print("✅ Patches: Up to date")
        else:
            print(f"❌ Patches: Recommend applying the Database Release Update (DBRU) to version {target_display}")
    else:
        print("❌ Patches: Unable to determine versions for comparison")

    # Controlfile redundancy
    print(_check_controlfile_redundancy(file_content))

    # Redo redundancy (multiple groups => redundancy)
    print(_check_redo_redundancy(file_content))

# Backward-compat alias (if you referenced v3 earlier)
check_oracle_config_v3 = check_oracle_config


# ----------------------------
# Optional CLI (standalone use)
# ----------------------------
if __name__ == "__main__":
    import argparse, sys, pathlib

    ap = argparse.ArgumentParser(description="Check Oracle version and storage redundancy from a text report.")
    ap.add_argument("file", help="Path to mfec_pm.txt-like file")
    ap.add_argument("target_version", nargs="?", default=None, help='Target RU (e.g., 19.27 or "19.27 (APR 2025)")')
    args = ap.parse_args()

    p = pathlib.Path(args.file)
    if not p.exists():
        sys.exit(f"Not found: {p}")

    content = p.read_text(encoding="utf-8", errors="ignore")
    if args.target_version is None:
        # If not provided, compare against the file's own major.minor so it prints "Up to date"
        fv = _extract_file_version(content)
        if fv:
            mm = ".".join(str(x) for x in _major_minor_tuple_from_str(fv))
            args.target_version = mm

    check_oracle_config(content, args.target_version or "")
