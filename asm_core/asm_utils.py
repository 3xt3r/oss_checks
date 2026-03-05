#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# asm_core/asm_utils.py

from __future__ import annotations

import re
from pathlib import Path

VOL_SKIP_RE = re.compile(r"\s*(?:__?volatile__?(?:\s+goto)?)\b", re.IGNORECASE)

_FILE_CACHE: dict[str, tuple[str, list[int]]] = {}


def _decode_basic_c_escapes(s: str) -> str:
    return s.replace("\\n", "\n").replace("\\t", "\t").replace("\\r", "\n")


def _get_text_and_line_offsets(p: Path) -> tuple[str, list[int]]:
    key = str(p)
    if key in _FILE_CACHE:
        return _FILE_CACHE[key]
    try:
        text = p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        text = ""
    offs = [0]
    i = 0
    while True:
        j = text.find("\n", i)
        if j == -1:
            break
        offs.append(j + 1)
        i = j + 1
    _FILE_CACHE[key] = (text, offs)
    return text, offs


def get_line_range_text(p: Path, center_lno: int, before: int = 20, after: int = 20) -> str:
    if center_lno is None or center_lno <= 0:
        return ""

    text, offs = _get_text_and_line_offsets(p)
    if not text or not offs:
        return ""

    total_lines = len(offs)
    start_lno = max(1, center_lno - before)
    end_lno = min(total_lines, center_lno + after)

    out_lines: list[str] = []
    for ln in range(start_lno, end_lno + 1):
        start = offs[ln - 1]
        end = offs[ln] - 1 if ln < total_lines else len(text)
        line = text[start:end]
        if line.endswith("\r"):
            line = line[:-1]
        mark = ">>" if ln == center_lno else "  "
        out_lines.append(f"{mark}{ln:6d}: {line}")
    return "\n".join(out_lines)


def _skip_optional_volatile(text: str, idx: int) -> int:
    i = idx
    while True:
        m = VOL_SKIP_RE.match(text, i)
        if not m:
            break
        i = m.end()
    while i < len(text) and text[i].isspace():
        i += 1
    return i


def _skip_ws_continuations_and_comments(text: str, idx: int) -> int:
    i = idx
    n = len(text)
    while i < n:
        moved = False
        while i < n and text[i].isspace():
            i += 1
            moved = True
        if i + 1 < n and text[i] == "\\" and text[i + 1] == "\n":
            i += 2
            moved = True
            continue
        if i + 2 < n and text[i] == "\\" and text[i + 1] == "\r" and text[i + 2] == "\n":
            i += 3
            moved = True
            continue
        if i + 1 < n and text[i] == "/" and text[i + 1] == "/":
            i += 2
            while i < n and text[i] != "\n":
                i += 1
            moved = True
            continue
        if i + 1 < n and text[i] == "/" and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            if i + 1 < n:
                i += 2
            moved = True
            continue
        if not moved:
            break
    return i


def _slice_gcc_raw_and_joined(text: str, start_pos: int) -> tuple[str | None, str | None, int | None]:
    i = start_pos - 1
    while i >= 0 and text[i].isspace():
        i -= 1
    while i >= 0 and (text[i].isalpha() or text[i] == "_"):
        i -= 1
    token_start = max(0, i + 1)

    s = text[start_pos:]
    o = s.find("(")
    if o < 0:
        return None, None, None
    pos0 = start_pos + o
    i = pos0 + 1
    depth = 1
    joined_lits: list[str] = []
    n = len(text)

    while i < n and depth > 0:
        ch = text[i]
        if ch == "(":
            depth += 1
            i += 1
        elif ch == ")":
            depth -= 1
            i += 1
            if depth == 0:
                break
        elif ch in ('"', "'"):
            q = ch
            i += 1
            lit = []
            while i < n:
                c2 = text[i]
                i += 1
                if c2 == "\\" and i < n:
                    nxt = text[i]
                    lit.append("\\")
                    lit.append(nxt)
                    i += 1
                    continue
                if c2 == q:
                    break
                lit.append(c2)
            joined_lits.append("".join(lit))
        elif ch == "/":
            if i + 1 < n and text[i + 1] == "/":
                i += 2
                while i < n and text[i] != "\n":
                    i += 1
            elif i + 1 < n and text[i + 1] == "*":
                i += 2
                while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                    i += 1
                if i + 1 < n:
                    i += 2
            else:
                i += 1
        else:
            i += 1

    if depth != 0:
        return None, None, None

    raw_snippet = text[token_start:i]
    joined_for_mn = _decode_basic_c_escapes("".join(joined_lits))
    return raw_snippet, joined_for_mn, i


def _slice_msvc_raw(text: str, token_start: int, token_end: int) -> tuple[str | None, str | None, list[str] | None]:
    i = token_end
    i = _skip_ws_continuations_and_comments(text, i)
    if i < len(text) and text[i] == "{":
        depth = 0
        j = i
        while j < len(text):
            ch = text[j]
            if ch == "{":
                depth += 1
                j += 1
            elif ch == "}":
                depth -= 1
                j += 1
                if depth == 0:
                    break
            elif ch in ('"', "'"):
                q = ch
                j += 1
                while j < len(text):
                    c2 = text[j]
                    j += 1
                    if c2 == "\\" and j < len(text):
                        j += 1
                        continue
                    if c2 == q:
                        break
            else:
                j += 1
        if depth != 0:
            return None, None, None
        k = _skip_ws_continuations_and_comments(text, j)
        if k < len(text) and text[k] == ";":
            j = k + 1
        raw = text[token_start:j]
        body_end = text.rfind("}", i, j)
        body = text[i + 1: body_end] if body_end != -1 else text[i + 1: j - 1]
        lines = body.splitlines()
        return raw, body, lines
    else:
        eol = text.find("\n", i)
        if eol < 0:
            eol = len(text)
        raw = text[token_start:eol]
        body = text[i:eol]
        return raw, body, [body]
