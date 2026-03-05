#!/usr/bin/env python3
from pathlib import Path
import argparse
import pandas as pd

MAX_SHEETNAME_LEN = 31

def safe_sheet_name(name: str) -> str:
    for bad in [":", "\\", "/", "?", "*", "[", "]"]:
        name = name.replace(bad, "_")
    return name[:MAX_SHEETNAME_LEN]

def merge_report(root: Path, outdir: Path, report_name: str, asm_sheet_order: list[str] | None):
    files = sorted(root.rglob(report_name))
    if not files:
        print(f"[SKIP] Not found: {report_name}")
        return

    sheets_map: dict[str, list[pd.DataFrame]] = {}

    for f in files:
        try:
            xls = pd.ExcelFile(f, engine="openpyxl")
        except Exception as e:
            print(f"[WARN] Cannot open {f}: {e}")
            continue

        for sheet in xls.sheet_names:
            try:
                df = pd.read_excel(f, sheet_name=sheet, engine="openpyxl")
            except Exception as e:
                print(f"[WARN] Cannot read sheet '{sheet}' from {f}: {e}")
                continue

            if df is None or df.empty:
                continue

            df.insert(0, "__source_dir__", str(f.parent))
            df.insert(0, "__source_file__", str(f))
            sheets_map.setdefault(sheet, []).append(df)

    if not sheets_map:
        print(f"[WARN] {report_name}: no sheets with data")
        return

    out_path = outdir / report_name
    with pd.ExcelWriter(out_path, engine="openpyxl") as writer:
        written = set()

        if asm_sheet_order:
            for sheet in asm_sheet_order:
                if sheet in sheets_map:
                    merged = pd.concat(sheets_map[sheet], ignore_index=True, sort=False)
                    merged.to_excel(writer, index=False, sheet_name=safe_sheet_name(sheet))
                    written.add(sheet)

        for sheet in sorted(sheets_map.keys()):
            if sheet in written:
                continue
            merged = pd.concat(sheets_map[sheet], ignore_index=True, sort=False)
            merged.to_excel(writer, index=False, sheet_name=safe_sheet_name(sheet))

        summary_rows = []
        for sheet, parts in sheets_map.items():
            summary_rows.append({
                "sheet": sheet,
                "rows_total": int(sum(len(p) for p in parts)),
                "files_with_sheet": int(len(parts)),
            })
        pd.DataFrame(summary_rows).to_excel(writer, index=False, sheet_name="__summary__")

    print(f"[OK] {report_name}: {len(files)} files -> {out_path} (sheets: {len(sheets_map)})")

def main():
    parser = argparse.ArgumentParser(description="Merge Excel reports from subdirectories")
    parser.add_argument("root", help="Root directory to search for reports")
    parser.add_argument("outdir", help="Output directory for merged reports")
    parser.add_argument(
        "--reports",
        default="asm_audit_root.xlsx,binary_libraries_root.xlsx,licenses.xlsx,trivy.xlsx",
        help="Comma-separated list of report file names"
    )
    parser.add_argument(
        "--asm-sheet-order",
        default="InlineHits,AsmFiles,OtherHits,GrepMismatches,SummaryFull,AsmBuildHits,OtherBuildHits",
        help="Comma-separated sheet order for asm report (optional)"
    )

    args = parser.parse_args()

    root = Path(args.root).resolve()
    outdir = Path(args.outdir).resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    report_names = [r.strip() for r in args.reports.split(",") if r.strip()]
    asm_sheet_order = [s.strip() for s in args.asm_sheet_order.split(",") if s.strip()]

    print(f"ROOT   = {root}")
    print(f"OUTDIR = {outdir}")

    for name in report_names:
        if name == "asm_audit_root.xlsx":
            merge_report(root, outdir, name, asm_sheet_order)
        else:
            merge_report(root, outdir, name, None)

if __name__ == "__main__":
    main()
