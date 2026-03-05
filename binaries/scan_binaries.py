#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Malware-relevant native binaries scanner (executables/libs).

Report includes ONLY potentially executable native binaries:
  - ELF
  - PE (Windows)
  - Mach-O (macOS, incl. fat)

Containers (ZIP/JAR/APK), bytecode and object files are excluded by default.

Extras:
  - SHA256
  - Size
  - Entropy
  - Suspicious hits (quick triage)
  - Source URL (from _checks/transitive_libs.log.csv when file is under transitive_libs/)

IMPORTANT:
  - If NO binaries are found: the function does NOT create an XLSX at all (returns 0).
"""

from __future__ import annotations

import csv
import hashlib
import math
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set

import pandas as pd


DEFAULT_EXTENSIONS_NATIVE = {
    ".so", ".dll", ".dylib", ".exe", ".pyd", ".ko",
}

EXCLUDE_DIRS = {
    ".git", "__pycache__", "pycache", "node_modules",
    "venv", ".idea", ".vscode",
    "_checks",  # avoid scanning our own artifacts folder
}

EXCLUDE_SUFFIXES = {
    ".zip", ".jar", ".apk", ".aar",
    ".class", ".o", ".obj", ".a", ".lib",
    ".pyc", ".pyo",
}

SUSPICIOUS_BYTE_PATTERNS = [
    b"/bin/sh", b"/bin/bash", b"powershell", b"cmd.exe",
    b"curl ", b"wget ", b"invoke-webrequest",
    b"virtualalloc", b"writeprocessmemory",
    b"loadlibrary", b"getprocaddress",
    b"mimikatz", b"meterpreter",
    b".onion", b"monero",
    b"http://", b"https://",
]

SUSPICIOUS_REGEXES = [
    re.compile(rb"\b[A-Za-z0-9+/]{80,}={0,2}\b"),
]


def _safe_dir_name(s: str) -> str:
    s = (s or "").strip()
    s = s.replace("\\", "_").replace("/", "_")
    return re.sub(r"[^A-Za-z0-9_.@\-\+]+", "_", s)


def make_relative_path(path: str, root: str) -> str:
    try:
        rel = os.path.relpath(path, root)
        return rel.replace("\\", "/")
    except Exception:
        return path.replace("\\", "/")


def _read_magic(path: str, n: int = 16) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(n)
    except Exception:
        return b""


def detect_magic_type(path: str) -> str:
    sig = _read_magic(path, 16)
    if not sig:
        return ""

    if sig.startswith(b"\x7fELF"):
        return "ELF"

    if sig.startswith(b"MZ"):
        return "PE"

    MACHO_MAGICS = {
        b"\xFE\xED\xFA\xCE", b"\xCE\xFA\xED\xFE",
        b"\xFE\xED\xFA\xCF", b"\xCF\xFA\xED\xFE",
        b"\xCA\xFE\xBA\xBE", b"\xBE\xBA\xFE\xCA",
        b"\xCA\xFE\xBA\xBF", b"\xBF\xBA\xFE\xCA",
    }
    if sig[:4] in MACHO_MAGICS:
        return "Mach-O"

    return ""


def _is_excluded_by_suffix(filename: str) -> bool:
    p = Path(filename)
    suffixes = [s.lower() for s in p.suffixes]
    return any(s in EXCLUDE_SUFFIXES for s in suffixes)


def is_native_binary_candidate(filename: str) -> bool:
    if _is_excluded_by_suffix(filename):
        return False

    p = Path(filename)
    suffixes = [s.lower() for s in p.suffixes]
    if not suffixes:
        return False

    if ".so" in suffixes:
        return True

    return suffixes[-1] in DEFAULT_EXTENSIONS_NATIVE


def load_transitive_sources_index(transitive_log_csv: str) -> Dict[Tuple[str, str, str], str]:
    idx: Dict[Tuple[str, str, str], str] = {}
    if not transitive_log_csv or not os.path.isfile(transitive_log_csv):
        return idx

    try:
        with open(transitive_log_csv, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                eco = (row.get("ecosystem") or "").strip()
                name = (row.get("name") or "").strip()
                ver = (row.get("version") or "").strip()
                url = (row.get("primary_url") or "").strip()
                if eco and name and ver and url:
                    idx[(eco, _safe_dir_name(name), _safe_dir_name(ver))] = url
    except Exception:
        pass

    return idx


def infer_source_url_for_path(path: str, root: str, idx: Dict[Tuple[str, str, str], str]) -> str:
    try:
        rel = os.path.relpath(path, root)
    except ValueError:
        return ""
    parts = rel.split(os.sep)

    try:
        i = parts.index("transitive_libs")
    except ValueError:
        return ""

    if len(parts) < i + 4:
        return ""

    eco = parts[i + 1]
    name = parts[i + 2]
    ver = parts[i + 3]

    return idx.get((eco, name, ver), "")


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for b in iter(lambda: f.read(1024 * 1024), b""):
                h.update(b)
        return h.hexdigest()
    except Exception:
        return ""


def file_entropy(path: str, max_bytes: int = 256 * 1024) -> float:
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
    except Exception:
        return float("nan")

    if not data:
        return 0.0

    freq = [0] * 256
    for b in data:
        freq[b] += 1

    ent = 0.0
    n = len(data)
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def suspicious_hits(path: str, max_bytes: int = 1024 * 1024) -> str:
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
    except Exception:
        return ""

    hits = set()
    low = data.lower()

    for p in SUSPICIOUS_BYTE_PATTERNS:
        if p in low:
            hits.add(p.decode(errors="ignore"))

    for rx in SUSPICIOUS_REGEXES:
        if rx.search(data):
            hits.add("looks_like_base64_blob")

    return "; ".join(sorted(hits))


def scan_tree(root: str, idx: Dict[Tuple[str, str, str], str], exclude_dirs: Optional[Set[str]] = None) -> List[Tuple]:
    results: List[Tuple] = []

    ex = set(EXCLUDE_DIRS)
    if exclude_dirs:
        ex |= {d for d in exclude_dirs if d}

    for r, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in ex]

        for f in files:
            full = os.path.join(r, f)

            if _is_excluded_by_suffix(f):
                continue

            if not is_native_binary_candidate(f):
                fmt = detect_magic_type(full)
                if fmt not in {"ELF", "PE", "Mach-O"}:
                    continue
                detection_type = f"magic:{fmt}"
            else:
                fmt = detect_magic_type(full)
                detection_type = "extension" if fmt else "extension(no-magic)"

            try:
                size = os.path.getsize(full)
            except Exception:
                size = -1

            results.append((
                make_relative_path(full, root),
                f,
                detection_type,
                fmt,
                size,
                file_sha256(full),
                file_entropy(full),
                suspicious_hits(full),
                infer_source_url_for_path(full, root, idx),
            ))

    return results


def write_excel(
    search_path: str,
    out_xlsx: str,
    transitive_log_csv: Optional[str] = None,
    exclude_dirs: Optional[Set[str]] = None,
) -> int:
    root = str(Path(search_path).resolve())

    if not transitive_log_csv:
        transitive_log_csv = str(Path(root) / "_checks" / "transitive_libs.log.csv")

    idx = load_transitive_sources_index(transitive_log_csv)
    rows = scan_tree(root, idx, exclude_dirs=exclude_dirs)

    # ✅ If empty -> do NOT create XLSX
    if not rows:
        print("[bin-scan] Found 0 native binary files")
        print("[bin-scan] Skipping XLSX output (empty)")
        return 0

    df = pd.DataFrame(
        rows,
        columns=[
            "path",
            "filename",
            "detection_type",
            "format",
            "size_bytes",
            "sha256",
            "entropy",
            "suspicious_hits",
            "source_url",
        ],
    )

    if not df.empty:
        df["entropy"] = df["entropy"].round(3)

    Path(out_xlsx).parent.mkdir(parents=True, exist_ok=True)
    df.to_excel(out_xlsx, index=False)

    print(f"[bin-scan] Found {len(df)} native binary files")
    print(f"[bin-scan] Report: {out_xlsx}")
    return int(len(df))


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("root")
    p.add_argument("--out", default="malware_binaries.xlsx")
    p.add_argument("--transitive-log-csv", default=None)
    p.add_argument("--exclude-dir", action="append", default=[], help="Exclude directories (repeatable)")
    a = p.parse_args()

    write_excel(
        a.root,
        a.out,
        a.transitive_log_csv,
        exclude_dirs=set(a.exclude_dir or []),
    )
