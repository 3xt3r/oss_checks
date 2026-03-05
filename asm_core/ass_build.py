#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
from pathlib import Path

from . import build_asm_hits


def parse_args():
    ap = argparse.ArgumentParser(description="Build asm hits audit")
    ap.add_argument("--root", default=".")
    ap.add_argument("--out", default="build_asm_hits.xlsx")
    ap.add_argument("--near-after", type=int, default=40)
    ap.add_argument("--exclude-dir", action="append", default=[], help="Exclude dir name (repeatable)")
    return ap.parse_args()


def main():
    args = parse_args()
    root = Path(args.root).resolve()
    out_path = Path(args.out)

    exclude_dirs = {x.strip().lower() for x in (args.exclude_dir or []) if x and x.strip()}

    found = build_asm_hits.write_excel(root, out_path, near_after=args.near_after, exclude_dirs=exclude_dirs)
    print(f"[ok] AsmBuildHits = {found}")
    print(f"[ok] saved: {out_path}")


if __name__ == "__main__":
    main()
