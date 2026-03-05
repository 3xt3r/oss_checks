#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import pandas as pd

from safe_versions_service import (
    build_safe_versions_and_catalog,
    ecosystem_from_purl,
    name_from_purl,
    version_from_purl,
    pick_safe_version_from_sbom_clean,
    pick_safe_version_nearest,
    normalize_version,
)


def _run_trivy_sbom(trivy_bin: str, sbom_path: Path, *, skip_db_update: bool) -> dict:
    cmd = [trivy_bin, "sbom"]
    if skip_db_update:
        cmd.append("--skip-db-update")
    cmd += ["--format", "json", str(sbom_path)]

    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = p.stdout.decode("utf-8", "ignore").strip()
    err = p.stderr.decode("utf-8", "ignore").strip()

    if p.returncode != 0:
        raise RuntimeError(f"trivy sbom failed rc={p.returncode}\nCMD: {' '.join(cmd)}\nERR: {err}")

    return json.loads(out) if out else {}


def trivy_sbom_report_func(trivy_bin: str, sbom_path: Path) -> dict:
    try:
        return _run_trivy_sbom(trivy_bin, sbom_path, skip_db_update=True)
    except Exception as e1:
        try:
            return _run_trivy_sbom(trivy_bin, sbom_path, skip_db_update=False)
        except Exception as e2:
            raise RuntimeError(f"{e1}\n\n--- fallback failed ---\n{e2}") from e2


def load_current_components_from_cdx(cdx: dict) -> Dict[Tuple[str, str], str]:
    out: Dict[Tuple[str, str], str] = {}
    for c in cdx.get("components") or []:
        purl = (c.get("purl") or "").strip()
        if not purl:
            continue
        eco = ecosystem_from_purl(purl)
        if eco == "other":
            continue
        name = name_from_purl(purl)
        ver = version_from_purl(purl)
        if name and ver:
            out[(eco, name)] = normalize_version(ver) or ver
    return out


def write_status(path: Path, status: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(status, indent=2), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-dir", required=True)
    ap.add_argument("--src-dir", required=True)
    ap.add_argument("--cdx", required=True)
    ap.add_argument("--trivy-fs", required=True)
    ap.add_argument("--trivy-bin", default="trivy")
    args = ap.parse_args()

    job_dir = Path(args.job_dir).resolve()
    src_dir = Path(args.src_dir).resolve()
    cdx_path = Path(args.cdx).resolve()
    trivy_fs_path = Path(args.trivy_fs).resolve()

    artifacts_dir = job_dir / "_checks"
    status_path = artifacts_dir / "safe_versions_status.json"

    if not job_dir.is_dir():
        print(f"[ERR] job-dir not found: {job_dir}")
        sys.exit(2)
    if not cdx_path.is_file():
        print(f"[ERR] cdx not found: {cdx_path}")
        write_status(status_path, {"ok": False, "reason": "cdx_missing", "cdx": str(cdx_path)})
        sys.exit(2)
    if not trivy_fs_path.is_file():
        print(f"[ERR] trivy-fs not found: {trivy_fs_path}")
        write_status(status_path, {"ok": False, "reason": "trivy_fs_missing", "trivy_fs": str(trivy_fs_path)})
        sys.exit(2)

    artifacts_dir.mkdir(parents=True, exist_ok=True)

    original_cdx = json.loads(cdx_path.read_text(encoding="utf-8"))
    trivy_fs_json = json.loads(trivy_fs_path.read_text(encoding="utf-8"))

    def _trivy_sbom_func(sbom_all_versions_path: Path) -> dict:
        return trivy_sbom_report_func(args.trivy_bin, sbom_all_versions_path)

    try:
        build_safe_versions_and_catalog(
            src_dir=src_dir,
            artifacts_dir=artifacts_dir,
            original_cdx_sbom=original_cdx,
            trivy_sbom_report_func=_trivy_sbom_func,
            trivy_fs_json_report=trivy_fs_json,
        )
    except Exception as e:
        msg = str(e)
        print("[safe] FAILED to build safe versions")
        print(msg)
        write_status(
            status_path,
            {
                "ok": False,
                "reason": "build_failed",
                "error": msg,
                "hint": "Most common: Trivy vuln DB cannot be updated/downloaded due to network/DNS. "
                        "Try running trivy once with working internet OR configure DNS/proxy, "
                        "then rerun with --skip-db-update.",
            },
        )
        sys.exit(0)

    sbom_clean = artifacts_dir / "sbom-clean.json"
    if not sbom_clean.is_file():
        print("[safe] sbom-clean.json not produced")
        write_status(status_path, {"ok": True, "reason": "no_vulnerable_packages", "xlsx": None})
        sys.exit(0)

    current = load_current_components_from_cdx(original_cdx)

    rows: List[dict] = []
    for (eco, name), installed in sorted(current.items()):
        safe_min = pick_safe_version_nearest(
            sbom_clean,
            target_ecosystem=eco,
            target_name=name,
            installed_version=installed,
        )

        safe_max = pick_safe_version_from_sbom_clean(
            sbom_clean,
            target_ecosystem=eco,
            target_name=name,
            mode="max",
        )

        if safe_min or safe_max:
            rows.append(
                {
                    "ecosystem": eco,
                    "name": name,
                    "installed_version": installed,
                    "safe_min": safe_min or "",
                    "safe_max": safe_max or "",
                }
            )

    out_xlsx = job_dir / "safe_versions.xlsx"

    if not rows:
        print("[safe] No safe versions found. XLSX not created.")
        write_status(status_path, {"ok": True, "reason": "no_safe_versions_found", "xlsx": None})
        sys.exit(0)

    df = pd.DataFrame(rows, columns=["ecosystem", "name", "installed_version", "safe_min", "safe_max"])
    df.to_excel(out_xlsx, index=False)

    print(f"[safe] saved: {out_xlsx}")
    write_status(status_path, {"ok": True, "reason": "ok", "xlsx": str(out_xlsx), "rows": len(df)})


if __name__ == "__main__":
    main()
