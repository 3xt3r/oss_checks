#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

import pandas as pd

from .asm_utils import (
    _get_text_and_line_offsets,
    get_line_range_text,
    _skip_optional_volatile,
    _skip_ws_continuations_and_comments,
    _slice_gcc_raw_and_joined,
    _slice_msvc_raw,
)

ASM_EXT = {".s", ".S", ".asm"}

INLINE_EXT = {
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".inl",
    ".m", ".mm",
    ".cu", ".cuh",
    ".rs", ".d", ".zig",
    ".pas", ".pp", ".inc",
}
INLINE_EXT_LOWER = {e.lower() for e in INLINE_EXT}

IGNORED_DIRS = {"test", "tests", "example", "examples"}

ASM_TOKEN_RE = re.compile(
    r"\b(?:_asm|__asm__|__asm|asm)\b"
    r"(?:\s+__?volatile__?\b(?:\s+goto\b)?)?",
    re.IGNORECASE,
)

TRUE_ASM_WORD_RE = re.compile(
    r"(^|[^A-Za-z0-9_])(?:_asm|__asm__|__asm|asm)([^A-Za-z0-9_]|$)",
    re.IGNORECASE,
)

def parse_args():
    ap = argparse.ArgumentParser(description="Inline asm audit (no arch, no mnemonic)")
    ap.add_argument("--root", default=".")
    ap.add_argument("--out", default="asm_audit.xlsx")
    ap.add_argument("--ctx-before", type=int, default=20)
    ap.add_argument("--ctx-after", type=int, default=20)
    return ap.parse_args()

def file_is_ignored(p: Path) -> bool:
    return any(part.lower() in IGNORED_DIRS for part in p.parts)


def run_grep(root: Path) -> list[str]:
    try:
        out = subprocess.check_output(
            ["bash", "-lc", "grep -rin asm ."],
            cwd=str(root),
            stderr=subprocess.STDOUT,
        )
        return [ln for ln in out.decode("utf-8", "ignore").splitlines() if ln.strip()]
    except subprocess.CalledProcessError as e:
        return [ln for ln in e.output.decode("utf-8", "ignore").splitlines() if ln.strip()]
    except Exception as ex:
        print(f"[ERR] grep failed: {ex}", file=sys.stderr)
        return []


def parse_grep_line(line: str):
    # ./path:line:content
    p1 = line.find(":")
    if p1 < 0:
        return line, None, "", line
    p2 = line.find(":", p1 + 1)
    if p2 < 0:
        return line[:p1], None, line[p1 + 1:], line
    try:
        lno = int(line[p1 + 1:p2])
    except Exception:
        lno = None
    return line[:p1], lno, line[p2 + 1:], line


def extract_inline_asm(p: Path, lno: int) -> str | None:
    text, offs = _get_text_and_line_offsets(p)
    if not text or not offs or not lno or lno <= 0 or lno - 1 >= len(offs):
        return None

    start = offs[lno - 1]
    m = ASM_TOKEN_RE.search(text, pos=start)
    if not m:
        return None

    token_start, token_end = m.start(), m.end()

    j = _skip_optional_volatile(text, token_end)
    j = _skip_ws_continuations_and_comments(text, j)

    raw, _, end_pos = _slice_gcc_raw_and_joined(text, token_end)
    if raw and end_pos:
        return text[token_start:end_pos]

    raw, _, _ = _slice_msvc_raw(text, token_start, m.end())
    return raw

def main():
    args = parse_args()
    root = Path(args.root).resolve()

    rows_inline: list[dict] = []
    rows_other: list[dict] = []

    for ln in run_grep(root):
        path, lno, payload, full = parse_grep_line(ln)

        gp = Path(path)
        if str(gp).startswith("./"):
            gp = Path(str(gp)[2:])
        p = (root / gp).resolve()

        if not p.is_file() or file_is_ignored(p):
            continue
        if p.suffix in ASM_EXT:
            continue
        if p.suffix.lower() not in INLINE_EXT_LOWER:
            continue
        if not TRUE_ASM_WORD_RE.search(payload or ""):
            continue

        raw = extract_inline_asm(p, lno or 0)
        if not raw:
            rows_other.append(
                {
                    "File": str(p),
                    "Line": lno or "",
                    "GrepLine": full.strip(),
                }
            )
            continue

        ctx = get_line_range_text(
            p,
            int(lno or 1),
            before=args.ctx_before,
            after=args.ctx_after,
        )

        rows_inline.append(
            {
                "File": str(p),
                "Line": lno or "",
                "GrepLine": full.strip(),
                "AsmRaw": raw,
                "Context": ctx,
            }
        )

    df_inline = pd.DataFrame(
        rows_inline,
        columns=["File", "Line", "GrepLine", "AsmRaw", "Context"],
    )
    if not df_inline.empty:
        df_inline.sort_values(by=["File", "Line"], ascending=[True, True], inplace=True)

    df_other = pd.DataFrame(
        rows_other,
        columns=["File", "Line", "GrepLine"],
    )
    if not df_other.empty:
        df_other.sort_values(by=["File", "Line"], ascending=[True, True], inplace=True)

    with pd.ExcelWriter(args.out, engine="xlsxwriter") as xw:
        df_inline.to_excel(xw, sheet_name="InlineHits", index=False)
        df_other.to_excel(xw, sheet_name="OtherHits", index=False)

    print(f"[ok] inline rows = {len(df_inline)}")
    print(f"[ok] other rows  = {len(df_other)}")
    print(f"[ok] saved: {args.out}")


if __name__ == "__main__":
    main()
