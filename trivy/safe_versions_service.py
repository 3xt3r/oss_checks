from __future__ import annotations

import json
import re
import uuid
import xml.etree.ElementTree as ET
from bisect import bisect_left
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import quote, unquote

import requests
from packaging.version import InvalidVersion, Version


INCLUDE_PRERELEASES_PYPI = False
INCLUDE_YANKED_PYPI = False
INCLUDE_PRERELEASES_NPM = False
INCLUDE_PRERELEASES_NUGET = False
INCLUDE_PRERELEASES_CARGO = False
INCLUDE_YANKED_CARGO = False
INCLUDE_PRERELEASES_GOLANG = False
INCLUDE_PRERELEASES_COMPOSER = False
INCLUDE_PRERELEASES_MAVEN = False

PYPI_URL = "https://pypi.org/pypi/{}/json"
NPM_REGISTRY_URL = "https://registry.npmjs.org/{}"
NUGET_VERSIONS_URL = "https://api.nuget.org/v3-flatcontainer/{}/index.json"
CARGO_CRATES_URL = "https://crates.io/api/v1/crates/{}"
GO_PROXY_LIST_URL = "https://proxy.golang.org/{}/@v/list"
PACKAGIST_P2_URL = "https://repo.packagist.org/p2/{}.json"
MAVEN_REPO1 = "https://repo1.maven.org/maven2"


def http_get(url: str, headers: Optional[Dict[str, str]] = None, timeout: int = 30, retries: int = 3):
    last = None
    for _ in range(retries):
        try:
            r = requests.get(url, headers=headers or {}, timeout=timeout)
            r.raise_for_status()
            return r
        except Exception as e:
            last = e
    raise RuntimeError(f"GET failed: {url}: {last}")


@dataclass(frozen=True)
class VulnItem:
    vuln_id: str
    severity: str


_SEMVER_RE = re.compile(
    r"^\s*v?(?P<maj>\d+)"
    r"(?:\.(?P<min>\d+))?"
    r"(?:\.(?P<pat>\d+))?"
    r"(?:\.(?P<restnum>\d+))?"
    r"(?P<tail>.*)$",
    re.IGNORECASE,
)

_PRERELEASE_SPLIT_RE = re.compile(r"[-+]", re.IGNORECASE)
_PRERELEASE_TOKEN_RE = re.compile(r"^(alpha|a|beta|b|rc|pre|preview)(\d*)$", re.IGNORECASE)


def normalize_version(v: str) -> str:
    s = (v or "").strip()
    if not s:
        return ""
    if s[:1].lower() == "v" and len(s) > 1 and s[1].isdigit():
        s = s[1:]
    return s.strip()


def _prerelease_key(tail: str) -> Tuple[int, int, str]:
    if not tail:
        return (9, 0, "")
    t = tail.strip()
    if t.startswith(("-", ".")):
        t = t[1:].strip()
    head = t.split(".", 1)[0].strip()

    m = _PRERELEASE_TOKEN_RE.match(head)
    if not m:
        return (50, 0, t.lower())

    token = (m.group(1) or "").lower()
    num_s = (m.group(2) or "").strip()
    num = int(num_s) if num_s.isdigit() else 0

    rank_map = {"alpha": 0, "a": 0, "beta": 1, "b": 1, "pre": 2, "preview": 2, "rc": 3}
    return (rank_map.get(token, 50), num, token)


def version_key(v: str) -> tuple:
    raw = (v or "").strip()
    nv = normalize_version(raw)
    if not nv:
        return (2, "")

    try:
        return (0, Version(nv))
    except InvalidVersion:
        pass

    m = _SEMVER_RE.match(nv)
    if m:
        maj = int(m.group("maj") or 0)
        mi = int(m.group("min") or 0)
        pa = int(m.group("pat") or 0)
        r4 = int(m.group("restnum") or 0)
        tail = (m.group("tail") or "").strip()

        parts = _PRERELEASE_SPLIT_RE.split(tail, 1) if tail else [""]
        pre = parts[0] if parts else ""
        if pre and not pre.startswith(("-", ".")) and not pre[0].isalnum():
            pre = ""

        if pre:
            pre_rank, pre_num, pre_raw = _prerelease_key(pre)
            return (1, maj, mi, pa, r4, 0, pre_rank, pre_num, pre_raw, nv.lower())
        return (1, maj, mi, pa, r4, 1, 9, 0, "", nv.lower())

    return (2, nv.lower())


def sort_versions_generic(versions: List[str]) -> List[str]:
    uniq = list(dict.fromkeys([v for v in versions if (v or "").strip()]))
    return sorted(uniq, key=version_key)


def is_prerelease_dash(v: str) -> bool:
    return "-" in (v or "")


def ecosystem_from_purl(purl: str) -> str:
    purl = (purl or "").strip().lower()
    if purl.startswith("pkg:pypi/"):
        return "pypi"
    if purl.startswith("pkg:npm/"):
        return "npm"
    if purl.startswith("pkg:nuget/"):
        return "nuget"
    if purl.startswith("pkg:cargo/"):
        return "cargo"
    if purl.startswith("pkg:golang/") or purl.startswith("pkg:go/"):
        return "golang"
    if purl.startswith("pkg:composer/"):
        return "composer"
    if purl.startswith("pkg:maven/"):
        return "maven"
    return "other"


def name_from_purl(purl: str) -> Optional[str]:
    if not (purl or "").startswith("pkg:"):
        return None
    try:
        tail = purl.split("/", 1)[1]
        name_part = tail.split("@", 1)[0].strip()
        name_part = name_part.split("?", 1)[0].strip()
        return unquote(name_part)
    except Exception:
        return None


def version_from_purl(purl: str) -> Optional[str]:
    if not (purl or "").startswith("pkg:"):
        return None
    if "@" not in purl:
        return None
    try:
        v = purl.split("@", 1)[1].strip()
        v = v.split("?", 1)[0].strip()
        return normalize_version(v)
    except Exception:
        return None


def npm_registry_name(pkg: str) -> str:
    return quote(pkg, safe="")


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


def get_versions_from_pypi(pkg: str) -> List[str]:
    data = http_get(PYPI_URL.format(pkg)).json()
    out = []
    for v, files in (data.get("releases") or {}).items():
        if not INCLUDE_YANKED_PYPI and any(f.get("yanked") for f in files or []):
            continue
        v_norm = normalize_version(v)
        try:
            if not INCLUDE_PRERELEASES_PYPI and Version(v_norm).is_prerelease:
                continue
        except InvalidVersion:
            continue
        out.append(v_norm or v)
    return sort_versions_generic(out)


def get_versions_from_npm(pkg: str) -> List[str]:
    data = http_get(NPM_REGISTRY_URL.format(npm_registry_name(pkg))).json()
    vers = [normalize_version(v) for v in (data.get("versions") or {}).keys()]
    vers = [v for v in vers if v]
    if not INCLUDE_PRERELEASES_NPM:
        vers = [v for v in vers if not is_prerelease_dash(v)]
    return sort_versions_generic(vers)


def get_versions_from_nuget(pkg: str) -> List[str]:
    data = http_get(NUGET_VERSIONS_URL.format(pkg.lower())).json()
    vers = [normalize_version(v) for v in (data.get("versions") or [])]
    vers = [v for v in vers if v]
    if not INCLUDE_PRERELEASES_NUGET:
        vers = [v for v in vers if not is_prerelease_dash(v)]
    return sort_versions_generic(vers)


def get_versions_from_cargo(crate: str) -> List[str]:
    data = http_get(CARGO_CRATES_URL.format(crate)).json()
    out = []
    for v in data.get("versions") or []:
        num = v.get("num")
        if not num:
            continue
        if not INCLUDE_YANKED_CARGO and v.get("yanked"):
            continue
        num_norm = normalize_version(num)
        try:
            if not INCLUDE_PRERELEASES_CARGO and Version(num_norm).is_prerelease:
                continue
        except InvalidVersion:
            continue
        out.append(num_norm or num)
    return sort_versions_generic(out)


def get_versions_from_golang(module: str) -> List[str]:
    text = http_get(
        GO_PROXY_LIST_URL.format(quote(module, safe="")),
        headers={"Accept": "text/plain"},
    ).text
    vers = [normalize_version(v) for v in text.splitlines() if v]
    vers = [v for v in vers if v]
    if not INCLUDE_PRERELEASES_GOLANG:
        vers = [v for v in vers if not is_prerelease_dash(v)]
    return sort_versions_generic(vers)


def get_versions_from_composer(pkg: str) -> List[str]:
    data = http_get(PACKAGIST_P2_URL.format(quote(pkg, safe=""))).json()
    vers = []
    for p in (data.get("packages") or {}).get(pkg) or []:
        v = (p.get("version") or "").strip()
        if not v:
            continue
        low = v.lower()
        if not INCLUDE_PRERELEASES_COMPOSER and (
            "dev" in low or "alpha" in low or "beta" in low or "rc" in low or "-" in v
        ):
            continue
        vers.append(normalize_version(v) or v)
    return sort_versions_generic(list(set(vers)))


def parse_maven_name(name: str) -> Optional[Tuple[str, str]]:
    if "/" not in name:
        return None
    g, a = name.split("/", 1)
    return (g.strip(), a.strip()) if g and a else None


def get_versions_from_maven(name: str) -> List[str]:
    ga = parse_maven_name(name)
    if not ga:
        return []
    g, a = ga
    url = f"{MAVEN_REPO1}/{g.replace('.', '/')}/{a}/maven-metadata.xml"
    root = ET.fromstring(http_get(url).text)
    vers = [normalize_version(n.text or "") for n in root.findall(".//version") if (n.text or "").strip()]
    vers = [v for v in vers if v]
    if not INCLUDE_PRERELEASES_MAVEN:
        vers = [v for v in vers if "-" not in v.lower()]
    return sort_versions_generic(list(dict.fromkeys(vers)))


def _severity_rank(sev: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get((sev or "").upper(), 9)


def _best_severity_from_cdx_vuln(v: dict) -> str:
    best = "UNKNOWN"
    for r in v.get("ratings") or []:
        sev = (r.get("severity") or "").upper()
        if _severity_rank(sev) < _severity_rank(best):
            best = sev
    return best


def compute_compact_vulns_from_cdx(original_cdx_sbom: dict) -> Dict[Tuple[str, str], List[VulnItem]]:
    out: Dict[Tuple[str, str], List[VulnItem]] = defaultdict(list)
    seen: Set[Tuple[str, str, str]] = set()

    def norm(ref: str) -> str:
        s = (ref or "").strip()
        if "#" in s:
            s = s.split("#", 1)[1]
        if "?" in s:
            s = s.split("?", 1)[0]
        return s.strip()

    key_by_ref: Dict[str, Tuple[str, str]] = {}

    for c in original_cdx_sbom.get("components") or []:
        bom_ref = c.get("bom-ref")
        purl = norm(c.get("purl") or "")
        eco = ecosystem_from_purl(purl)
        if eco == "other":
            continue
        name = name_from_purl(purl) or c.get("name")
        if not name:
            continue
        if bom_ref:
            key_by_ref[norm(bom_ref)] = (eco, name)
        if purl:
            key_by_ref[purl] = (eco, name)

    for v in original_cdx_sbom.get("vulnerabilities") or []:
        vid = v.get("id")
        if not vid:
            continue
        sev = _best_severity_from_cdx_vuln(v)
        for a in v.get("affects") or []:
            ref = norm(a.get("ref"))
            key = key_by_ref.get(ref)
            if not key:
                eco = ecosystem_from_purl(ref)
                name = name_from_purl(ref)
                if eco != "other" and name:
                    key = (eco, name)
            if not key:
                continue
            k = (*key, f"{sev} {vid}")
            if k in seen:
                continue
            seen.add(k)
            out[key].append(VulnItem(vuln_id=vid, severity=sev))

    for k in out:
        out[k].sort(key=lambda x: (_severity_rank(x.severity), x.vuln_id))
    return out


def compute_vulnerable_from_trivy_fs_json(trivy_fs_json_report: dict) -> Dict[str, Set[str]]:
    vulnerable: Dict[str, Set[str]] = defaultdict(set)

    for r in trivy_fs_json_report.get("Results", []) or []:
        r_type = str(r.get("Type") or "").strip()
        eco_hint = _guess_ecosystem_from_trivy_type(r_type)

        for v in r.get("Vulnerabilities") or []:
            pid = v.get("PkgIdentifier") or {}
            purl = ""
            if isinstance(pid, dict):
                purl = str(pid.get("PURL") or "").strip()

            if purl:
                eco = ecosystem_from_purl(purl)
                name = name_from_purl(purl)
                if eco != "other" and name:
                    vulnerable[eco].add(name)
                    continue

            pkg_name = str(v.get("PkgName") or "").strip()
            if eco_hint != "other" and pkg_name:
                if eco_hint == "maven" and ":" in pkg_name and "/" not in pkg_name:
                    pkg_name = pkg_name.replace(":", "/", 1)
                vulnerable[eco_hint].add(pkg_name)

    return vulnerable


def load_safe_versions_from_sbom_clean(sbom_clean_path: Path) -> Dict[Tuple[str, str], List[str]]:
    data = json.loads(sbom_clean_path.read_text(encoding="utf-8"))
    out: Dict[Tuple[str, str], List[str]] = defaultdict(list)

    for c in data.get("components") or []:
        purl = (c.get("purl") or "").strip()
        name = (c.get("name") or "").strip()
        ver = (c.get("version") or "").strip()

        eco = ecosystem_from_purl(purl) if purl else "other"
        if eco == "other":
            continue

        if not name and purl:
            name = name_from_purl(purl) or ""
        if (not ver) and purl:
            ver = version_from_purl(purl) or ""

        ver = normalize_version(ver)
        if not name or not ver:
            continue

        out[(eco, name)].append(ver)

    for k in list(out.keys()):
        out[k] = sort_versions_generic(out[k])

    return out


def pick_safe_version_from_sbom_clean(
    sbom_clean_path: Path,
    *,
    target_purl: Optional[str] = None,
    target_ecosystem: Optional[str] = None,
    target_name: Optional[str] = None,
    mode: str = "min",
) -> Optional[str]:
    if target_purl:
        eco = ecosystem_from_purl(target_purl)
        name = name_from_purl(target_purl) or ""
    else:
        eco = (target_ecosystem or "").strip().lower()
        name = (target_name or "").strip()

    if not eco or eco == "other" or not name:
        return None

    m = load_safe_versions_from_sbom_clean(sbom_clean_path)
    vers = m.get((eco, name)) or []
    if not vers:
        return None

    if (mode or "min").lower() == "max":
        return vers[-1]
    return vers[0]


def pick_safe_version_nearest(
    sbom_clean_path: Path,
    *,
    target_purl: Optional[str] = None,
    target_ecosystem: Optional[str] = None,
    target_name: Optional[str] = None,
    installed_version: Optional[str] = None,
) -> Optional[str]:
    if target_purl:
        eco = ecosystem_from_purl(target_purl)
        name = name_from_purl(target_purl) or ""
    else:
        eco = (target_ecosystem or "").strip().lower()
        name = (target_name or "").strip()

    if not eco or eco == "other" or not name:
        return None

    inst = normalize_version(installed_version or "")
    if not inst:
        return None

    m = load_safe_versions_from_sbom_clean(sbom_clean_path)
    vers = m.get((eco, name)) or []
    if not vers:
        return None

    keys = [version_key(v) for v in vers]
    inst_k = version_key(inst)

    i = bisect_left(keys, inst_k)
    if i < len(vers):
        return vers[i]
    return vers[-1]


def build_safe_versions_and_catalog(
    *,
    src_dir: Path,
    artifacts_dir: Path,
    original_cdx_sbom: dict,
    trivy_sbom_report_func,
    trivy_fs_json_report: Optional[dict] = None,
) -> None:
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    all_versions_path = artifacts_dir / "sbom-all-versions.json"
    clean_path = artifacts_dir / "sbom-clean.json"

    vulns_map = compute_compact_vulns_from_cdx(original_cdx_sbom)
    vulnerable: Dict[str, Set[str]] = defaultdict(set)
    for (eco, name), vulns in vulns_map.items():
        if vulns:
            vulnerable[eco].add(name)

    if not any(vulnerable.values()) and trivy_fs_json_report:
        vulnerable = compute_vulnerable_from_trivy_fs_json(trivy_fs_json_report)

    if not any(vulnerable.values()):
        empty = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []}
        clean_path.write_text(json.dumps(empty, indent=2), encoding="utf-8")
        try:
            all_versions_path.unlink(missing_ok=True)
        except Exception:
            pass
        return

    components: List[dict] = []

    def add_versions(eco: str, pkg: str, versions: List[str]) -> None:
        for ver in versions:
            vv = normalize_version(ver) or ver
            components.append(
                {
                    "type": "library",
                    "name": pkg,
                    "version": vv,
                    "purl": f"pkg:{eco}/{pkg}@{vv}",
                    "bom-ref": f"{eco}::{pkg}@{vv}-{uuid.uuid4()}",
                }
            )

    for eco, pkgs in vulnerable.items():
        for pkg in sorted(pkgs):
            if eco == "pypi":
                add_versions(eco, pkg, get_versions_from_pypi(pkg))
            elif eco == "npm":
                add_versions(eco, pkg, get_versions_from_npm(pkg))
            elif eco == "nuget":
                add_versions(eco, pkg, get_versions_from_nuget(pkg))
            elif eco == "cargo":
                add_versions(eco, pkg, get_versions_from_cargo(pkg))
            elif eco == "golang":
                add_versions(eco, pkg, get_versions_from_golang(pkg))
            elif eco == "composer":
                add_versions(eco, pkg, get_versions_from_composer(pkg))
            elif eco == "maven":
                add_versions(eco, pkg, get_versions_from_maven(pkg))

    raw = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": components}
    all_versions_path.write_text(json.dumps(raw, indent=2), encoding="utf-8")

    report = trivy_sbom_report_func(all_versions_path) or {}

    purl_by_name_ver: Dict[Tuple[str, str], str] = {}
    for c in components:
        n = (c.get("name") or "").strip()
        v = normalize_version((c.get("version") or "").strip())
        p = (c.get("purl") or "").strip()
        if n and v and p:
            purl_by_name_ver[(n, v)] = p

    bad_purls: Set[str] = set()
    bad_bomrefs: Set[str] = set()

    for r in report.get("Results", []) or []:
        for v in (r.get("Vulnerabilities") or []):
            pid = v.get("PkgIdentifier") or {}
            purl = (pid.get("PURL") or "").strip()
            if purl:
                bad_purls.add(purl)

            bomref = (pid.get("BOMRef") or "").strip()
            if bomref:
                bad_bomrefs.add(bomref)

            pkg_name = (v.get("PkgName") or "").strip()
            inst_ver = normalize_version((v.get("InstalledVersion") or "").strip())
            if pkg_name and inst_ver:
                p = purl_by_name_ver.get((pkg_name, inst_ver))
                if p:
                    bad_purls.add(p)

    safe = []
    for c in components:
        p = (c.get("purl") or "").strip()
        br = (c.get("bom-ref") or "").strip()
        if p and p in bad_purls:
            continue
        if br and br in bad_bomrefs:
            continue
        safe.append(c)

    clean_path.write_text(json.dumps({**raw, "components": safe}, indent=2), encoding="utf-8")

    try:
        all_versions_path.unlink(missing_ok=True)
    except Exception:
        pass
