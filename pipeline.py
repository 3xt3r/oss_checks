#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import subprocess
import sys
import uuid
from pathlib import Path

import pandas as pd

from _cleanup.cleanup_non_main import delete_non_main_code
from instruments.java import hide_template_poms, restore_hidden_poms


def run(cmd, cwd=None) -> int:
    pretty = " ".join(str(x) for x in cmd)
    print(f"[RUN] {pretty} (cwd={cwd or Path.cwd()})")
    rc = subprocess.run(cmd, cwd=cwd).returncode
    if rc != 0:
        print(f"[ERR] rc={rc}: {pretty}")
        sys.exit(rc)
    return 0


def _unique_sheet_name(name: str, used: set[str], max_len: int = 31) -> str:
    base = (name or "Sheet").strip()[:max_len] or "Sheet"
    if base not in used:
        used.add(base)
        return base
    i = 2
    while True:
        suffix = f"_{i}"
        cut = max_len - len(suffix)
        cand = (base[:cut] + suffix)[:max_len]
        if cand not in used:
            used.add(cand)
            return cand
        i += 1


def merge_binary_excels(files: list[tuple[str, Path]], out_file: Path) -> None:
    existing = [(label, path) for label, path in files if path.is_file()]
    if not existing:
        print("[WARN] binary merge: no input xlsx; skipping")
        return

    out_file.parent.mkdir(parents=True, exist_ok=True)
    used: set[str] = set()

    with pd.ExcelWriter(out_file, engine="xlsxwriter") as writer:
        for label, path in existing:
            with pd.ExcelFile(path) as xls:
                for sheet in xls.sheet_names:
                    df = pd.read_excel(xls, sheet_name=sheet)
                    name = _unique_sheet_name(f"{label}__{sheet}", used)
                    df.to_excel(writer, sheet_name=name, index=False)


def run_asm_audit(job_dir: Path, project_root: Path, deps_root: Path, instruments_root: Path) -> None:
    targets = [(project_root, "root")]
    if deps_root.is_dir():
        targets.append((deps_root, "transitive_libs"))

    out_file = job_dir / "asm_audit.xlsx"
    produced: list[tuple[str, Path, Path]] = []

    for scan_root, label in targets:
        asm_tmp = job_dir / f"__asm_audit__{label}__asm_tmp.xlsx"
        build_tmp = job_dir / f"__asm_audit__{label}__build_tmp.xlsx"

        if label == "root":
            exclude_args = ["--exclude-dir", "jobs", "--exclude-dir", "transitive_libs", "--exclude-dir", "_checks"]
        else:
            exclude_args = ["--exclude-dir", "_checks", "--exclude-dir", "jobs"]

        run(
            ["python3", "-m", "asm_core.assembler", "--root", str(scan_root), "--out", str(asm_tmp)],
            cwd=str(instruments_root),
        )

        run(
            ["python3", "-m", "asm_core.ass_build", "--root", str(scan_root), "--out", str(build_tmp), *exclude_args],
            cwd=str(instruments_root),
        )

        produced.append((label, asm_tmp, build_tmp))

    used: set[str] = set()
    with pd.ExcelWriter(out_file, engine="xlsxwriter") as writer:
        for label, asm_tmp, build_tmp in produced:
            for tmp, suffix in [(asm_tmp, ""), (build_tmp, "__build")]:
                if tmp.is_file():
                    with pd.ExcelFile(tmp) as xls:
                        for sheet in xls.sheet_names:
                            df = pd.read_excel(xls, sheet_name=sheet)
                            name = _unique_sheet_name(f"{label}{suffix}__{sheet}", used)
                            df.to_excel(writer, sheet_name=name, index=False)


def extract_and_cleanup(target_dir: Path, extract_script: Path, cwd_for_extract: Path) -> None:
    run(["python3", str(extract_script), str(target_dir)], cwd=str(cwd_for_extract))
    delete_non_main_code(str(target_dir))


def require_file(path: Path, message: str):
    if not path.is_file():
        print(f"[ERR] missing required file: {path}")
        print(f"[HINT] {message}")
        sys.exit(2)


def run_trivy(root: Path, args, sbom_path: Path, licenses_sbom: Path):
    hidden = hide_template_poms(root)
    try:
        run(
            [
                args.trivy_bin, "fs", ".", "-f", "json",
                "-o", str(sbom_path),
                "--timeout", str(args.trivy_timeout),
            ],
            cwd=str(root),
        )
        run(
            [
                args.trivy_bin, "fs", ".",
                "--format", "cyclonedx",
                "--output", str(licenses_sbom),
                "--timeout", str(args.trivy_timeout),
            ],
            cwd=str(root),
        )
    finally:
        restore_hidden_poms(hidden, root)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("root")
    p.add_argument("--jobs-dir", default="jobs")
    p.add_argument("--run-id", default=None)
    p.add_argument("--trivy-bin", default="trivy")
    p.add_argument("--trivy-timeout", default="30m")
    p.add_argument("--sbom-name", default="trivy.json")
    p.add_argument("--licenses-sbom-name", default="sbom.cdx.json")
    p.add_argument("--out-dir", default="transitive_libs")
    p.add_argument("--apply", action="store_true")

    group = p.add_mutually_exclusive_group()
    group.add_argument("--lock", action="store_true")
    group.add_argument("--trivy", action="store_true")
    group.add_argument("--save-transitives", action="store_true")
    group.add_argument("--binaries", action="store_true")
    group.add_argument("--asm", action="store_true")
    group.add_argument("--licenses", action="store_true")

    args = p.parse_args()

    root = Path(args.root).resolve()
    if not root.is_dir():
        sys.exit("Root directory not found")

    here = Path(__file__).resolve().parent

    run_id = args.run_id or uuid.uuid4().hex
    job_dir = (root.parent / args.jobs_dir / run_id).resolve()
    job_dir.mkdir(parents=True, exist_ok=True)

    ecosystem_scan_script = here / "ecosystem/ecosystem_scan.py"
    lock_gen_script = here / "ecosystem/generate_locks.py"
    extract_script = here / "_extract/extract_archives.py"
    download_script = here / "trivy/download_sources_from_sbom.py"
    bin_scan_script = here / "binaries/scan_binaries.py"
    licenses_script = here / "license/collect_licenses.py"

    sbom_path = job_dir / args.sbom_name
    licenses_sbom = job_dir / args.licenses_sbom_name
    deps_dir = job_dir / args.out_dir

    mode = "all"
    if args.lock:
        mode = "lock"
    elif args.trivy:
        mode = "trivy"
    elif args.save_transitives:
        mode = "transitives"
    elif args.binaries:
        mode = "binaries"
    elif args.asm:
        mode = "asm"
    elif args.licenses:
        mode = "licenses"

    extract_and_cleanup(root, extract_script, root)

    if mode in ("all", "lock"):
        run(["python3", str(ecosystem_scan_script), str(root)], cwd=str(root))
        lock_cmd = ["python3", str(lock_gen_script), str(root)]
        if args.apply:
            lock_cmd.append("--apply")
        run(lock_cmd, cwd=str(root))
        if mode == "lock":
            return

    if mode in ("all", "trivy"):
        run_trivy(root, args, sbom_path, licenses_sbom)
        if mode == "trivy":
            return

    if mode in ("all", "transitives"):
        require_file(sbom_path, "Run with --trivy or --licenses first (same --run-id if you want to reuse)")
        run(["python3", str(download_script), str(sbom_path), "--out-dir", str(deps_dir)], cwd=str(here))
        if deps_dir.is_dir():
            extract_and_cleanup(deps_dir, extract_script, root)
        if mode == "transitives":
            return

    if mode in ("all", "binaries"):
        bin_tmp_root = job_dir / "__binary_libraries__root__tmp.xlsx"
        bin_tmp_trans = job_dir / "__binary_libraries__transitive_libs__tmp.xlsx"

        run(
            [
                "python3", str(bin_scan_script),
                str(root),
                "--out", str(bin_tmp_root),
                "--exclude-dir", "jobs",
                "--exclude-dir", "transitive_libs",
                "--exclude-dir", "_checks",
            ],
            cwd=str(here),
        )

        if deps_dir.is_dir():
            trans_log = deps_dir / "_checks" / "transitive_libs.log.csv"
            cmd = [
                "python3", str(bin_scan_script),
                str(deps_dir),
                "--out", str(bin_tmp_trans),
                "--exclude-dir", "_checks",
            ]
            if trans_log.is_file():
                cmd += ["--transitive-log-csv", str(trans_log)]
            run(cmd, cwd=str(here))

        merge_binary_excels(
            [("root", bin_tmp_root), ("transitive_libs", bin_tmp_trans)],
            job_dir / "binary_libraries.xlsx",
        )

        for tmp in (bin_tmp_root, bin_tmp_trans):
            if tmp.is_file():
                try:
                    tmp.unlink()
                except Exception:
                    pass

        if mode == "binaries":
            return

    if mode in ("all", "asm"):
        run_asm_audit(job_dir, root, deps_dir, here)
        if mode == "asm":
            return

    if mode in ("all", "licenses"):
        if not licenses_sbom.is_file():
            run_trivy(root, args, sbom_path, licenses_sbom)
        require_file(licenses_sbom, "Trivy did not produce sbom.cdx.json for this run-id")
        run(["python3", str(licenses_script), str(licenses_sbom), "--sources-dir", str(deps_dir)], cwd=str(here))
        if mode == "licenses":
            return


if __name__ == "__main__":
    main()
