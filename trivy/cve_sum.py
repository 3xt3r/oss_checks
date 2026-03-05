#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
from pathlib import Path
from collections import defaultdict, deque
from typing import Dict, Tuple, Optional, List
from urllib.parse import unquote

import pandas as pd

ROOT_RELATIONSHIPS = {"direct", "workspace"}


def _ecosystem_from_purl(purl: str) -> str:
    p = (purl or "").strip().lower()
    if p.startswith("pkg:pypi/"):
        return "pypi"
    if p.startswith("pkg:npm/"):
        return "npm"
    if p.startswith("pkg:nuget/"):
        return "nuget"
    if p.startswith("pkg:cargo/"):
        return "cargo"
    if p.startswith("pkg:golang/") or p.startswith("pkg:go/"):
        return "golang"
    if p.startswith("pkg:composer/"):
        return "composer"
    if p.startswith("pkg:maven/"):
        return "maven"
    return "other"


def _name_from_purl(purl: str) -> Optional[str]:
    if not (purl or "").startswith("pkg:"):
        return None
    try:
        tail = purl.split("/", 1)[1]
        name_part = tail.split("@", 1)[0].strip()
        name_part = name_part.split("?", 1)[0].strip()
        return unquote(name_part)
    except Exception:
        return None


def _guess_ecosystem_from_trivy_type(t: str) -> str:
    t = (t or "").strip().lower()
    if t in ("pip", "python", "pypi"):
        return "pypi"
    if t in ("npm", "yarn"):
        return "npm"
    if t in ("nuget",):
        return "nuget"
    if t in ("cargo",):
        return "cargo"
    if t in ("gomod", "go", "golang"):
        return "golang"
    if t in ("composer",):
        return "composer"
    if t in ("maven", "jar", "pom", "gradle"):
        return "maven"
    return "other"


def _normalize_name_for_ecosystem(eco: str, name: str) -> str:
    eco = (eco or "").lower().strip()
    n = (name or "").strip()
    if eco == "maven":
        if ":" in n and "/" not in n:
            return n.replace(":", "/", 1)
    return n


def _add_safe_map_aliases(
    out: Dict[Tuple[str, str], Tuple[str, str]],
    eco: str,
    name: str,
    safe_min: str,
    safe_max: str
) -> None:
    eco = (eco or "").strip().lower()
    n0 = _normalize_name_for_ecosystem(eco, name)
    if not eco or not n0:
        return

    out[(eco, n0)] = (safe_min, safe_max)

    if eco == "maven":
        if "/" in n0 and ":" not in n0:
            out[(eco, n0.replace("/", ":", 1))] = (safe_min, safe_max)
        if ":" in n0 and "/" not in n0:
            out[(eco, n0.replace(":", "/", 1))] = (safe_min, safe_max)


def load_safe_versions_map(safe_xlsx: Path) -> Dict[Tuple[str, str], Tuple[str, str]]:
    if not safe_xlsx or not safe_xlsx.is_file():
        return {}

    try:
        df = pd.read_excel(safe_xlsx)
    except Exception:
        return {}

    cols = {c.lower().strip(): c for c in df.columns}
    need = ["ecosystem", "name", "safe_min", "safe_max"]
    if any(k not in cols for k in need):
        return {}

    out: Dict[Tuple[str, str], Tuple[str, str]] = {}
    for _, r in df.iterrows():
        eco = str(r[cols["ecosystem"]] or "").strip().lower()
        name = str(r[cols["name"]] or "").strip()
        if not eco or not name:
            continue
        safe_min = str(r[cols["safe_min"]] or "").strip()
        safe_max = str(r[cols["safe_max"]] or "").strip()
        _add_safe_map_aliases(out, eco, name, safe_min, safe_max)

    return out


def find_safe_versions_xlsx(in_path: Path, explicit: Optional[Path] = None) -> Optional[Path]:
    candidates: List[Path] = []
    if explicit:
        candidates.append(explicit)

    candidates.append(in_path.parent / "safe_versions.xlsx")
    candidates.append(in_path.parent / "_checks" / "safe_versions.xlsx")
    candidates.append(in_path.parent.parent / "_checks" / "safe_versions.xlsx")

    cur = in_path.parent
    for _ in range(6):
        candidates.append(cur / "safe_versions.xlsx")
        candidates.append(cur / "_checks" / "safe_versions.xlsx")
        if cur.parent == cur:
            break
        cur = cur.parent

    seen = set()
    for c in candidates:
        if not c:
            continue
        try:
            c2 = c.resolve()
        except Exception:
            c2 = c
        if str(c2) in seen:
            continue
        seen.add(str(c2))
        if c2.is_file():
            return c2
    return None


def load_trivy_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def build_graph(packages):
    parents = defaultdict(set)
    roots = set()

    for p in packages or []:
        pid = (p.get("ID") or "").strip()
        if not pid:
            continue

        rel = (p.get("Relationship") or "").lower()
        if rel in ROOT_RELATIONSHIPS:
            roots.add(pid)

        for dep in p.get("DependsOn") or []:
            if dep:
                parents[dep].add(pid)

    return parents, roots


def find_chain(pkg_id, parents, roots):
    if not pkg_id:
        return ""

    if pkg_id in roots:
        return pkg_id

    q = deque([pkg_id])
    prev = {pkg_id: None}
    found = None

    while q:
        cur = q.popleft()
        for par in parents.get(cur, []):
            if par in prev:
                continue
            prev[par] = cur
            if par in roots:
                found = par
                q.clear()
                break
            q.append(par)

    if not found:
        return ""

    chain = [found]
    cur = found
    while prev[cur]:
        cur = prev[cur]
        chain.append(cur)

    return " -> ".join(chain)


def extract_rows(data, safe_map: Dict[Tuple[str, str], Tuple[str, str]]):
    rows = []
    reports = [data] if isinstance(data, dict) else data

    for report in reports:
        for result in report.get("Results", []):
            target = (result.get("Target") or "").strip()
            packages = result.get("Packages") or []
            vulns = result.get("Vulnerabilities") or []

            parents, roots = build_graph(packages)

            r_type = str(result.get("Type") or "").strip()
            eco_hint = _guess_ecosystem_from_trivy_type(r_type)

            for v in vulns:
                pkg_name = (v.get("PkgName") or "").strip()
                ver = (v.get("InstalledVersion") or "").strip()
                pkg_id = (v.get("PkgID") or "").strip()

                package = f"{pkg_name} {ver}".strip() if pkg_name else pkg_id
                vuln_id = (v.get("VulnerabilityID") or "").strip()
                severity = (v.get("Severity") or "").upper().strip()

                chain = find_chain(pkg_id, parents, roots)
                dependency_chain = f"{target} -> {chain}" if chain else target

                safe_min = ""
                safe_max = ""

                purl = ""
                pid = v.get("PkgIdentifier") or {}
                if isinstance(pid, dict):
                    purl = str(pid.get("PURL") or "").strip()

                if purl:
                    eco = _ecosystem_from_purl(purl)
                    name = _name_from_purl(purl) or ""
                    if eco != "other" and name:
                        key = (eco, _normalize_name_for_ecosystem(eco, name))
                        sm = safe_map.get(key)
                        if sm:
                            safe_min, safe_max = sm
                else:
                    if eco_hint != "other" and pkg_name:
                        n = _normalize_name_for_ecosystem(eco_hint, pkg_name)
                        sm = safe_map.get((eco_hint, n))
                        if sm:
                            safe_min, safe_max = sm

                rows.append(
                    {
                        "Package": package,
                        "VulnerabilityID": vuln_id,
                        "Severity": severity,
                        "DependencyChain": dependency_chain,
                        "SafeMin": safe_min,
                        "SafeMax": safe_max,
                    }
                )

    return rows


def main():
    if len(sys.argv) not in (2, 3, 4):
        print("Usage: python3 cve_sum.py trivy.json [output.xlsx] [safe_versions.xlsx]")
        sys.exit(1)

    in_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2]) if len(sys.argv) >= 3 else in_path.with_suffix(".xlsx")

    explicit_safe = Path(sys.argv[3]) if len(sys.argv) == 4 else None
    safe_found = find_safe_versions_xlsx(in_path, explicit=explicit_safe)

    safe_map: Dict[Tuple[str, str], Tuple[str, str]] = {}
    if safe_found:
        safe_map = load_safe_versions_map(safe_found)

    if safe_found and safe_map:
        print(f"[safe] loaded: {safe_found} ({len(safe_map)} keys)")
    elif safe_found and not safe_map:
        print(f"[safe] found but empty/unreadable: {safe_found} (SafeMin/SafeMax will be empty)")
    else:
        if explicit_safe:
            print(f"[safe] not found: {explicit_safe} (SafeMin/SafeMax will be empty)")
        else:
            print(f"[safe] not found around: {in_path} (SafeMin/SafeMax will be empty)")

    data = load_trivy_json(in_path)
    rows = extract_rows(data, safe_map)

    df = pd.DataFrame(
        rows,
        columns=[
            "Package",
            "VulnerabilityID",
            "Severity",
            "DependencyChain",
            "SafeMin",
            "SafeMax",
        ],
    )

    df.drop_duplicates(inplace=True)
    df.to_excel(out_path, index=False)

    print(f"[OK] Готово. Строк: {len(df)}")
    print(f"[OK] Файл: {out_path}")


if __name__ == "__main__":
    main()
