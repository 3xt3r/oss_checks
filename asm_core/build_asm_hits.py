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
    _skip_optional_volatile,
    _skip_ws_continuations_and_comments,
    _slice_gcc_raw_and_joined,
    _slice_msvc_raw,
)

BUILD_BASENAMES = {
    "Makefile", "makefile", "GNUmakefile", "Makefile.am", "Makefile.in",
    "configure", "configure.ac", "configure.in", "config.guess", "config.sub",
    "CMakeLists.txt",
    "meson.build", "meson_options.txt",
    "build.ninja",
    "BUILD", "BUILD.bazel", "WORKSPACE", "WORKSPACE.bazel",
    "SConstruct", "SConscript",
    "Cargo.toml", "build.rs",
    "build.gradle", "settings.gradle", "build.gradle.kts", "settings.gradle.kts",
    "pom.xml", "build.xml",
    "setup.py", "pyproject.toml",
    "Rakefile", "Gemfile",
    "package.json", "webpack.config.js", "gulpfile.js", "Gruntfile.js",
}

BUILD_SUFFIXES = {
    ".mk", ".ninja", ".cmake",
    ".am", ".in",
    ".bazel", ".bzl",
    ".pro", ".pri",
    ".vcxproj", ".csproj", ".sln", ".props", ".targets",
    ".xcodeproj", ".xcworkspace",
    ".inc", ".ini",
}

IGNORED_DIRS = {"test", "tests", "Testing", "example", "examples", "docs", "doc"}

ASM_TOKEN_RE_C = re.compile(
    r"\b(?:_asm|__asm__|__asm|asm)\b"
    r"(?:\s+__?volatile__?\b(?:\s+goto\b)?)?",
    re.IGNORECASE,
)

LABEL_RE = re.compile(r"^\s*(?:[A-Za-z_.$][\w.$]*|\d+[fb]?)\s*:\s*")
WORD_RE = re.compile(r"[A-Za-z.][A-Za-z0-9._]*")
PREFIXES = {"lock", "rep", "repe", "repz", "repne", "repnz"}
NON_INSTR_TOKENS = {"volatile"}
MASM_DIRECTIVES = {
    "align", "assume", "end", "endm", "proc", "endp", "segment", "ends", "org", "label",
    "db", "dw", "dd", "dq", "dt",
}


def parse_args():
    ap = argparse.ArgumentParser(description="Build asm hits")
    ap.add_argument("--root", default=".")
    ap.add_argument("--out", default="build_asm_hits.xlsx")
    ap.add_argument("--near-after", type=int, default=40)
    ap.add_argument("--exclude-dir", action="append", default=[], help="Exclude dir name (repeatable)")
    return ap.parse_args()


def is_build_file(p: Path) -> bool:
    name = p.name
    suf = p.suffix.lower()
    if name in BUILD_BASENAMES:
        return True
    if suf in BUILD_SUFFIXES:
        return True
    if name.startswith("Makefile."):
        return True
    return False


def file_is_ignored(p: Path, exclude_dirs: set[str]) -> bool:
    ign = {x.lower() for x in IGNORED_DIRS} | exclude_dirs
    return any(part.lower() in ign for part in p.parts)


def run_grep_markers(root: Path, exclude_dirs: set[str]) -> list[str]:
    excl_args = [f"--exclude-dir={d}" for d in sorted(exclude_dirs) if d]
    cmd = ["grep", "-rni", *excl_args, "asm", "."]

    p = subprocess.run(cmd, cwd=str(root), capture_output=True)
    out = (p.stdout + p.stderr).decode("utf-8", "ignore")

    if p.returncode == 0:
        return [ln for ln in out.splitlines() if ln.strip()]
    if p.returncode == 1:
        return []

    print(f"[ERR] grep failed rc={p.returncode}\nCMD={' '.join(cmd)}\n{out}", file=sys.stderr)
    return []


def parse_grep_line(line: str):
    p1 = line.find(":")
    if p1 < 0:
        return (line, None, "", line)
    p2 = line.find(":", p1 + 1)
    if p2 < 0:
        return (line[:p1], None, line[p1 + 1:], line)
    path = line[:p1]
    try:
        lno = int(line[p1 + 1:p2])
    except Exception:
        lno = None
    content = line[p2 + 1:]
    return (path, lno, content, line)


def strip_leading_labels(s: str) -> str:
    s2 = s.lstrip()
    while True:
        m = LABEL_RE.match(s2)
        if not m:
            break
        s2 = s2[m.end():].lstrip()
    return s2


def comment_chars_for_path(p: Path) -> list[str]:
    s = str(p).lower().replace("\\", "/")
    comment_chars = ["#"]
    if s.endswith(".inc"):
        comment_chars.append(";")
    return comment_chars


def strip_line_comments(s: str, comment_chars: list[str]) -> str:
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.DOTALL)
    for ch in comment_chars:
        if ch in s:
            s = s.split(ch, 1)[0]
    return s


def normalize_mnemonic(tok: str, assume_x86_widths: bool = True) -> str:
    t = tok.strip().lower().rstrip(";,:")
    if t.startswith("."):
        return t
    if t in MASM_DIRECTIVES or t in NON_INSTR_TOKENS:
        return ""
    if "." in t:
        t = t.split(".", 1)[0]
    if assume_x86_widths and len(t) >= 4 and t[-1] in ("b", "w", "l", "q", "d"):
        return t[:-1]
    return t


def _extract_from_segment(seg: str, treat_masm: bool) -> str | None:
    tokens = [m.group(0) for m in WORD_RE.finditer(seg)]
    if not tokens:
        return None
    i = 0
    while i < len(tokens) and tokens[i].lower() in PREFIXES:
        i += 1
    while i < len(tokens) and tokens[i].startswith("."):
        i += 1
    if i >= len(tokens):
        return None
    tok = tokens[i].lower()
    if tok in NON_INSTR_TOKENS:
        i += 1
        while i < len(tokens) and (tokens[i].startswith(".") or tokens[i].lower() in NON_INSTR_TOKENS):
            i += 1
        if i >= len(tokens):
            return None
        tok = tokens[i].lower()
    if treat_masm and tok in MASM_DIRECTIVES:
        return None
    return tokens[i]


def _all_mnemonics_from_lines(lines: list[str], comment_chars: list[str], treat_masm: bool) -> list[str]:
    out: list[str] = []
    for ln in lines:
        ls = strip_leading_labels(ln.strip())
        if not ls:
            continue
        code = strip_line_comments(ls, comment_chars)
        if not code.strip():
            continue
        segments = [code]
        if not treat_masm and (";" in code) and (";" not in comment_chars):
            segments = [s for s in code.split(";") if s.strip()]
        for seg in segments:
            mn = _extract_from_segment(seg, treat_masm=treat_masm)
            if mn:
                out.append(mn)
    return out


def extract_inline_asm_from_file(p: Path, lno: int, near_after: int) -> tuple[str, list[str], list[str]]:
    reasons: list[str] = []
    text, offs = _get_text_and_line_offsets(p)
    if not text or not offs or lno is None or lno <= 0 or lno - 1 >= len(offs):
        return "", [], ["no-text-or-bad-line"]

    start = offs[lno - 1]
    m = ASM_TOKEN_RE_C.search(text, pos=start)
    if not m:
        return "", [], ["no-asm-token-at-line"]

    token_start, token_end = m.start(), m.end()
    cmchars_base = comment_chars_for_path(p)

    j = _skip_optional_volatile(text, token_end)
    j = _skip_ws_continuations_and_comments(text, j)

    def parse_gcc():
        raw_gcc, joined_for_mn, _end_pos = _slice_gcc_raw_and_joined(text, token_end)
        if not raw_gcc:
            return "", [], ["asm-unclosed"]
        loc_reasons: list[str] = []
        mnems: list[str] = []
        if joined_for_mn is not None:
            if joined_for_mn.strip() == "":
                loc_reasons.append("asm-empty-template")
            mnems = _all_mnemonics_from_lines(joined_for_mn.splitlines(), comment_chars=cmchars_base, treat_masm=False)
        return raw_gcc.strip(), mnems, loc_reasons

    def parse_msvc():
        raw_msvc, _body, lines = _slice_msvc_raw(text, token_start, m.end())
        if not raw_msvc:
            return "", [], ["asm-unclosed"]
        loc_reasons = ["asm-msvc-block" if "{" in raw_msvc else "asm-msvc-line"]
        mnems = _all_mnemonics_from_lines(
            lines or [],
            comment_chars=(cmchars_base + ([] if ";" in cmchars_base else [";"])),
            treat_masm=True,
        )
        return raw_msvc.strip(), mnems, loc_reasons

    raw = ""
    mn: list[str] = []
    if j < len(text) and text[j] == "(":
        raw, mn, loc = parse_gcc()
        reasons.extend(loc)
    else:
        raw, mn, loc = parse_gcc()
        if raw:
            reasons.extend(loc)
        else:
            raw, mn, loc = parse_msvc()
            reasons.extend(loc)

    all_mnems_norm: list[str] = []
    if mn:
        for t in mn:
            tn = normalize_mnemonic(t, assume_x86_widths=True)
            if tn and not tn.isdigit():
                all_mnems_norm.append(tn)

    return raw, all_mnems_norm, reasons


def collect_build_dfs(root: Path, *, near_after: int = 40, exclude_dirs: set[str] | None = None) -> tuple[pd.DataFrame, pd.DataFrame]:
    root = Path(root).resolve()
    exclude_dirs = exclude_dirs or set()
    lines = run_grep_markers(root, exclude_dirs | {"node_modules", ".git", "__pycache__"})

    rows_hits: list[dict] = []
    rows_other: list[dict] = []

    for ln in lines:
        path, lno, payload, _full = parse_grep_line(ln)
        gp = Path(path)
        if str(gp).startswith("./"):
            gp = Path(str(gp)[2:])
        p = (root / gp).resolve()

        if not p.is_file() or file_is_ignored(p, exclude_dirs) or not is_build_file(p):
            continue

        snippet, mnems, reasons = extract_inline_asm_from_file(p, lno or 1, near_after)
        reason_str = "; ".join([r for r in (reasons or []) if r])

        if snippet.strip():
            rows_hits.append(
                {
                    "File": str(p),
                    "Line": lno if lno is not None else "",
                    "GrepLine": (payload or "").strip(),
                    "Snippet": snippet,
                    "Reason": reason_str,
                    "AllMnemonics": " ".join(mnems),
                }
            )
        else:
            rows_other.append(
                {
                    "File": str(p),
                    "Line": lno if lno is not None else "",
                    "GrepLine": (payload or "").strip(),
                    "Reason": reason_str or "no-snippet",
                }
            )

    df_hits = pd.DataFrame(rows_hits, columns=["File", "Line", "GrepLine", "Snippet", "Reason", "AllMnemonics"])
    if not df_hits.empty:
        df_hits.sort_values(by=["File", "Line"], ascending=[True, True], inplace=True)

    df_other = pd.DataFrame(rows_other, columns=["File", "Line", "GrepLine", "Reason"])
    if not df_other.empty:
        df_other.sort_values(by=["File", "Line"], ascending=[True, True], inplace=True)

    return df_hits, df_other


def write_excel(root: Path, out_path: Path, *, near_after: int = 40, exclude_dirs: set[str] | None = None) -> int:
    df_hits, df_other = collect_build_dfs(root, near_after=near_after, exclude_dirs=exclude_dirs)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with pd.ExcelWriter(out_path, engine="xlsxwriter") as xw:
        df_hits.to_excel(xw, sheet_name="AsmBuildHits", index=False)
        df_other.to_excel(xw, sheet_name="OtherBuildHits", index=False)

    return int(len(df_hits))


def main():
    args = parse_args()
    root = Path(args.root).resolve()
    out_path = Path(args.out)
    exclude_dirs = {x.strip().lower() for x in (args.exclude_dir or []) if x and x.strip()}
    found = write_excel(root, out_path, near_after=args.near_after, exclude_dirs=exclude_dirs)
    print(f"[ok] AsmBuildHits = {found}")
    print(f"[ok] saved: {out_path}")


if __name__ == "__main__":
    main()
