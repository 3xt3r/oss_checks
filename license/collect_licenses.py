#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import dataclasses
import fnmatch
import io
import json
import os
import re
import sys
import tarfile
import zipfile
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import unquote as url_unquote

import requests
import xml.etree.ElementTree as ET
from openpyxl import Workbook

try:
    import tomllib
except Exception:
    tomllib = None


@dataclasses.dataclass
class Package:
    ecosystem: str
    name: str
    version: str
    component_refs: List[str]
    pkg_id: Optional[str] = None
    license_sbom: Optional[str] = None
    purl: Optional[str] = None


SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "sbom-license-collector/1.1"})

HTTP_CACHE: Dict[str, object] = {}


def http_get_json(url: str, timeout: int = 30) -> Optional[dict]:
    if url in HTTP_CACHE:
        v = HTTP_CACHE[url]
        return v if isinstance(v, dict) else None
    try:
        r = SESSION.get(url, timeout=timeout)
        if r.status_code != 200:
            HTTP_CACHE[url] = None
            return None
        data = r.json()
        HTTP_CACHE[url] = data
        return data
    except Exception:
        HTTP_CACHE[url] = None
        return None


def http_get_text(url: str, timeout: int = 30) -> Optional[str]:
    if url in HTTP_CACHE:
        v = HTTP_CACHE[url]
        return v if isinstance(v, str) else None
    try:
        r = SESSION.get(url, timeout=timeout)
        if r.status_code != 200:
            HTTP_CACHE[url] = None
            return None
        HTTP_CACHE[url] = r.text
        return r.text
    except Exception:
        HTTP_CACHE[url] = None
        return None


def http_download_bytes(url: str, max_bytes: int = 60 * 1024 * 1024, timeout: int = 60) -> Optional[bytes]:
    cache_key = f"__bin__:{url}"
    if cache_key in HTTP_CACHE:
        v = HTTP_CACHE[cache_key]
        return v if isinstance(v, (bytes, bytearray)) else None
    try:
        with SESSION.get(url, stream=True, timeout=timeout, allow_redirects=True) as r:
            if r.status_code != 200:
                HTTP_CACHE[cache_key] = None
                return None
            buf = io.BytesIO()
            total = 0
            for chunk in r.iter_content(chunk_size=1024 * 128):
                if not chunk:
                    continue
                total += len(chunk)
                if total > max_bytes:
                    HTTP_CACHE[cache_key] = None
                    return None
                buf.write(chunk)
            data = buf.getvalue()
            HTTP_CACHE[cache_key] = data
            return data
    except Exception:
        HTTP_CACHE[cache_key] = None
        return None


def make_safe_dir_name(s: str) -> str:
    s = s.strip()
    s = s.replace("\\", "_").replace("/", "_")
    return re.sub(r"[^A-Za-z0-9_.@\-\+]+", "_", s)


def pkg_root_dir(sources_root: str, ecosystem: str, pkg: Package) -> str:
    safe_name = make_safe_dir_name(pkg.name)
    dirname = f"{safe_name}-{pkg.version}"
    return os.path.join(sources_root, ecosystem, dirname)


def find_first_file(root_dir: str, filename: str) -> Optional[str]:
    if not os.path.isdir(root_dir):
        return None
    for dirpath, _, filenames in os.walk(root_dir):
        if filename in filenames:
            return os.path.join(dirpath, filename)
    return None


def load_sbom(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def detect_ecosystem_from_pkgtype(pkg_type: str) -> Optional[str]:
    if not pkg_type:
        return None
    pkg_type = pkg_type.lower().strip()
    mapping = {
        "pip": "pypi",
        "python": "pypi",
        "npm": "npm",
        "yarn": "npm",
        "conan": "conan",
        "gomod": "go",
        "go": "go",
        "cargo": "cargo",
        "composer": "composer",
        "maven": "maven",
        "gradle": "maven",
        "pom": "maven",
        "jar": "maven",
        "war": "maven",
        "ear": "maven",
        "nuget": "nuget",
    }
    return mapping.get(pkg_type)


def extract_licenses_from_component(c: dict) -> Optional[str]:
    lic_list: List[str] = []
    for lic in c.get("licenses") or []:
        if not isinstance(lic, dict):
            continue
        if "expression" in lic and isinstance(lic["expression"], str):
            lic_list.append(lic["expression"])
        elif "license" in lic and isinstance(lic["license"], dict):
            lobj = lic["license"]
            if isinstance(lobj.get("id"), str):
                lic_list.append(lobj["id"])
            elif isinstance(lobj.get("name"), str):
                lic_list.append(lobj["name"])
    if not lic_list:
        return None
    return " OR ".join(sorted(set(x.strip() for x in lic_list if x and isinstance(x, str))))


def extract_packages_from_sbom(
    sbom: dict,
    include_ecosystems: Optional[Iterable[str]] = None,
) -> List[Package]:
    components = sbom.get("components", [])
    if include_ecosystems is not None:
        include_ecosystems = set(include_ecosystems)

    packages: Dict[Tuple[str, str, str], Package] = {}

    for comp in components:
        comp_ref = comp.get("bom-ref") or comp.get("purl") or comp.get("name") or "<unknown>"

        properties = comp.get("properties") or []
        props = {}
        for p in properties:
            if not isinstance(p, dict):
                continue
            name = p.get("name")
            value = p.get("value")
            if isinstance(name, str):
                props[name] = value

        lic_sbom = extract_licenses_from_component(comp)

        pkg_type_raw = props.get("aquasecurity:trivy:PkgType")
        ecosystem = detect_ecosystem_from_pkgtype(pkg_type_raw) if pkg_type_raw else None

        purl = comp.get("purl") or ""
        if not ecosystem and isinstance(purl, str):
            if purl.startswith("pkg:pypi/"):
                ecosystem = "pypi"
            elif purl.startswith("pkg:npm/"):
                ecosystem = "npm"
            elif purl.startswith("pkg:conan/"):
                ecosystem = "conan"
            elif purl.startswith("pkg:golang/") or purl.startswith("pkg:go/"):
                ecosystem = "go"
            elif purl.startswith("pkg:cargo/"):
                ecosystem = "cargo"
            elif purl.startswith("pkg:maven/"):
                ecosystem = "maven"
            elif purl.startswith("pkg:nuget/"):
                ecosystem = "nuget"
            elif purl.startswith("pkg:composer/"):
                ecosystem = "composer"

        if not ecosystem:
            continue
        if include_ecosystems and ecosystem not in include_ecosystems:
            continue

        name, version, pkg_id = None, None, None

        if ecosystem == "pypi":
            if isinstance(purl, str) and purl.startswith("pkg:pypi/"):
                tail = purl.split("pkg:pypi/", 1)[1]
                if "@" in tail:
                    name, version = tail.split("@", 1)
            if not name:
                name = comp.get("name")
            if not version:
                version = comp.get("version")

        elif ecosystem == "npm":
            pkg_id = props.get("aquasecurity:trivy:PkgID")
            if isinstance(pkg_id, str) and "@" in pkg_id:
                pkg_name, ver = pkg_id.rsplit("@", 1)
                name, version = pkg_name, ver
            else:
                group = comp.get("group")
                cname = comp.get("name")
                if group and cname:
                    if group.startswith("@"):
                        name = f"{group}/{cname}"
                    else:
                        name = f"@{group}/{cname}"
                else:
                    name = cname
                if isinstance(purl, str) and purl.startswith("pkg:npm/"):
                    tail = url_unquote(purl.split("pkg:npm/", 1)[1])
                    if "@" in tail:
                        n2, v2 = tail.rsplit("@", 1)
                        name = name or n2
                        version = version or v2
            if not version:
                version = comp.get("version")

        elif ecosystem == "go":
            pkg_id = props.get("aquasecurity:trivy:PkgID")
            if isinstance(pkg_id, str) and "@" in pkg_id:
                name, version = pkg_id.split("@", 1)
            elif isinstance(purl, str) and ("pkg:golang/" in purl or "pkg:go/" in purl):
                tail = url_unquote(
                    purl.split("pkg:golang/", 1)[1] if "pkg:golang/" in purl else purl.split("pkg:go/", 1)[1]
                )
                if "@" in tail:
                    name, version = tail.split("@", 1)
            if not name:
                name = comp.get("name")
            if version and not version.startswith("v"):
                version = "v" + version

        elif ecosystem == "cargo":
            if isinstance(purl, str) and purl.startswith("pkg:cargo/"):
                tail = url_unquote(purl.split("pkg:cargo/", 1)[1])
                if "@" in tail:
                    name, version = tail.split("@", 1)
            if not name:
                name = comp.get("name")
            if not version:
                version = comp.get("version")

        elif ecosystem == "maven":
            if isinstance(purl, str) and purl.startswith("pkg:maven/"):
                tail = url_unquote(purl.split("pkg:maven/", 1)[1])
                if "@" in tail:
                    ga, version = tail.split("@", 1)
                    if "/" in ga:
                        group, artifact = ga.split("/", 1)
                        name = f"{group}:{artifact}"
            if not name:
                group = comp.get("group")
                cname = comp.get("name")
                if group and cname:
                    name = f"{group}:{cname}"
            if not version:
                version = comp.get("version")

        elif ecosystem == "nuget":
            if isinstance(purl, str) and purl.startswith("pkg:nuget/"):
                tail = url_unquote(purl.split("pkg:nuget/", 1)[1])
                if "@" in tail:
                    name, version = tail.split("@", 1)
            if not name:
                name = comp.get("name")
            if not version:
                version = comp.get("version")

        elif ecosystem == "composer":
            if isinstance(purl, str) and purl.startswith("pkg:composer/"):
                tail = url_unquote(purl.split("pkg:composer/", 1)[1])
                if "@" in tail:
                    vp, version = tail.split("@", 1)
                    name = vp
            if not name:
                group = comp.get("group")
                cname = comp.get("name")
                if group and cname:
                    name = f"{group}/{cname}"
                else:
                    name = cname
            if not version:
                version = comp.get("version")

        if not name or not version:
            continue

        key = (ecosystem, name, version)
        cref = str(comp_ref)
        purl_s = purl if isinstance(purl, str) else None

        if key not in packages:
            packages[key] = Package(
                ecosystem=ecosystem,
                name=name,
                version=version,
                component_refs=[cref],
                pkg_id=pkg_id,
                license_sbom=lic_sbom,
                purl=purl_s,
            )
        else:
            if cref not in packages[key].component_refs:
                packages[key].component_refs.append(cref)
            if purl_s and purl_s not in packages[key].component_refs:
                packages[key].component_refs.append(purl_s)
            if not packages[key].license_sbom and lic_sbom:
                packages[key].license_sbom = lic_sbom
            if not packages[key].purl and purl_s:
                packages[key].purl = purl_s

    print(f"Found {len(packages)} unique (ecosystem, name, version) entries")
    return list(packages.values())


def build_cdx_dependency_graph(sbom: dict) -> Tuple[Dict[str, List[str]], List[str]]:
    deps = sbom.get("dependencies") or []
    graph: Dict[str, List[str]] = {}

    for d in deps:
        if not isinstance(d, dict):
            continue
        ref = d.get("ref")
        if not isinstance(ref, str) or not ref:
            continue
        depends_on = d.get("dependsOn") or []
        depends_on = [x for x in depends_on if isinstance(x, str) and x]
        graph[ref] = depends_on

    incoming = set()
    for _, children in graph.items():
        for ch in children:
            incoming.add(ch)

    roots = [n for n in graph.keys() if n not in incoming]

    meta = sbom.get("metadata") or {}
    mc = meta.get("component") or {}
    if isinstance(mc, dict):
        meta_ref = mc.get("bom-ref")
        if isinstance(meta_ref, str) and meta_ref:
            if meta_ref not in roots:
                roots.insert(0, meta_ref)

    roots = list(dict.fromkeys(roots))
    return graph, roots


def build_reverse_deps(graph: Dict[str, List[str]]) -> Dict[str, List[str]]:
    rev: Dict[str, List[str]] = {}
    for parent, deps in graph.items():
        for child in deps:
            rev.setdefault(child, []).append(parent)
    for k in list(rev.keys()):
        rev[k] = list(dict.fromkeys(rev[k]))
    return rev


def build_ref_label_map(sbom: dict) -> Dict[str, str]:
    m: Dict[str, str] = {}

    for c in sbom.get("components", []) or []:
        if not isinstance(c, dict):
            continue

        bom_ref = c.get("bom-ref")
        name = c.get("name")
        version = c.get("version")
        group = c.get("group")
        purl = c.get("purl")

        label = None
        if isinstance(group, str) and group and isinstance(name, str) and name:
            label = f"{group}:{name}"
        elif isinstance(name, str) and name:
            label = name

        if label and isinstance(version, str) and version:
            label = f"{label}@{version}"

        if not label and isinstance(purl, str) and purl:
            label = purl

        if isinstance(bom_ref, str) and bom_ref and label:
            m[bom_ref] = label
        if isinstance(purl, str) and purl and label:
            m[purl] = label

    meta = sbom.get("metadata", {})
    mc = meta.get("component", {})
    if isinstance(mc, dict):
        br = mc.get("bom-ref")
        nm = mc.get("name")
        if isinstance(br, str) and br:
            m[br] = nm if isinstance(nm, str) and nm else "application"

    return m


def find_all_paths_to_target(
    target_ref: str,
    parents: Dict[str, List[str]],
    roots: List[str],
    label_map: Dict[str, str],
    max_depth: int,
    max_paths: int,
) -> Tuple[List[str], bool]:
    roots_set = set(roots)
    truncated = False
    results: List[List[str]] = []

    stack: List[Tuple[str, List[str], set]] = [(target_ref, [target_ref], {target_ref})]

    while stack:
        node, path_rev, seen = stack.pop()
        if len(results) >= max_paths:
            truncated = True
            break
        if len(path_rev) > max_depth:
            continue

        if node in roots_set:
            results.append(list(reversed(path_rev)))
            continue

        for p in parents.get(node, []):
            if p in seen:
                continue
            stack.append((p, path_rev + [p], seen | {p}))

    out: List[str] = []
    seen_s = set()
    for p in results:
        s = " -> ".join(label_map.get(x, x) for x in p)
        if s not in seen_s:
            seen_s.add(s)
            out.append(s)

    return out, truncated


def all_paths_for_package(
    pkg: Package,
    parents: Dict[str, List[str]],
    roots: List[str],
    label_map: Dict[str, str],
    max_depth: int,
    max_paths_per_lib: int,
) -> str:
    all_paths: List[str] = []
    truncated_any = False

    for ref in pkg.component_refs:
        paths, truncated = find_all_paths_to_target(
            target_ref=ref,
            parents=parents,
            roots=roots,
            label_map=label_map,
            max_depth=max_depth,
            max_paths=max_paths_per_lib,
        )
        if paths:
            all_paths.extend(paths)
        if truncated:
            truncated_any = True

        if len(all_paths) >= max_paths_per_lib:
            truncated_any = True
            all_paths = all_paths[:max_paths_per_lib]
            break

    all_paths = list(dict.fromkeys(all_paths))
    if not all_paths:
        return ""
    if truncated_any:
        return "\n".join(all_paths) + "\n...[TRUNCATED]"
    return "\n".join(all_paths)


SPDX_TOKEN_RE = re.compile(r"^[A-Za-z0-9\.\-+]+$")


def normalize_spdx_expr(s: str) -> str:
    s = (s or "").strip()
    return " ".join(s.split())


def looks_like_spdx(s: str) -> bool:
    s = (s or "").strip()
    if not s:
        return False
    if " OR " in s or " AND " in s:
        return True
    return bool(SPDX_TOKEN_RE.match(s))


def combine_licenses(licenses: List[str]) -> str:
    items: List[str] = []
    for x in licenses:
        x = normalize_spdx_expr(x)
        if not x:
            continue
        items.append(x)
    items = list(dict.fromkeys(items))
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return " OR ".join(sorted(items))


LICENSE_NAME_PATTERNS = ["LICENSE", "LICENSE.*", "LICENSE-*", "COPYING", "COPYING.*", "UNLICENSE", "UNLICENSE.*"]


def is_probable_license_filename(name: str) -> bool:
    name_lower = name.lower()
    if name_lower.startswith(("license", "copying", "unlicense")):
        return True
    for pat in LICENSE_NAME_PATTERNS:
        if fnmatch.fnmatch(name, pat):
            return True
    return False


def guess_license_text(text: str) -> str:
    if not text:
        return ""
    t = text.lower()
    if "mit license" in t or "permission is hereby granted" in t:
        return "MIT"
    if "apache license" in t and ("version 2.0" in t or "version 2" in t):
        return "Apache-2.0"
    if "mozilla public license" in t and ("2.0" in t or "version 2.0" in t):
        return "MPL-2.0"
    if "eclipse public license" in t and ("2.0" in t or "version 2.0" in t):
        return "EPL-2.0"
    if "the unlicense" in t or "released into the public domain" in t:
        return "Unlicense"
    if "isc license" in t:
        return "ISC"
    if "gnu affero general public license" in t and ("version 3" in t or "3." in t):
        return "AGPL-3.0"
    if "gnu general public license" in t:
        if "version 3" in t or "3." in t:
            return "GPL-3.0"
        if "version 2" in t or "2." in t:
            return "GPL-2.0"
        return "GPL"
    if "gnu lesser general public license" in t:
        if "version 3" in t or "3." in t:
            return "LGPL-3.0"
        if "version 2.1" in t or "2.1" in t:
            return "LGPL-2.1"
        if "version 2" in t or "2." in t:
            return "LGPL-2.0"
        return "LGPL"
    if "redistribution and use in source and binary forms" in t:
        if "neither the name" in t:
            return "BSD-3-Clause"
        return "BSD-2-Clause"
    return ""


def find_license_files_in_dir(root_dir: str, max_files: int = 30) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    if not os.path.isdir(root_dir):
        return out

    try:
        for fname in sorted(os.listdir(root_dir)):
            fpath = os.path.join(root_dir, fname)
            if os.path.isfile(fpath) and is_probable_license_filename(fname):
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        txt = f.read(200000)
                    g = guess_license_text(txt)
                    if g:
                        out.append((g, fpath))
                        if len(out) >= max_files:
                            return out
                except Exception:
                    pass
    except OSError:
        return out

    for dirpath, _, filenames in os.walk(root_dir):
        for fname in sorted(filenames):
            if not is_probable_license_filename(fname):
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    txt = f.read(200000)
                g = guess_license_text(txt)
                if g:
                    out.append((g, fpath))
                    if len(out) >= max_files:
                        return out
            except Exception:
                continue
    return out


def detect_license_from_sources_generic(pkg: Package, sources_root: str) -> Optional[Tuple[str, str]]:
    root_dir = pkg_root_dir(sources_root, pkg.ecosystem, pkg)
    hits = find_license_files_in_dir(root_dir)
    if not hits:
        return None
    lic = combine_licenses([x for x, _ in hits])
    paths = [p for _, p in hits]
    details = paths[0] if len(paths) == 1 else f"{paths[0]} (+{len(paths)-1} more)"
    return lic, details


def normalize_composer_version(v: str) -> str:
    v = (v or "").strip()
    if v.startswith("v"):
        v = v[1:]
    if v.count(".") == 2:
        v = v + ".0"
    return v


def detect_composer_license_from_registry(pkg: Package) -> Optional[str]:
    if "/" not in pkg.name:
        return None
    vendor, package = pkg.name.split("/", 1)
    url = f"https://repo.packagist.org/p2/{vendor}/{package}.json"
    data = http_get_json(url)
    if not data:
        return None

    versions = data.get("packages", {}).get(pkg.name) or []
    want = normalize_composer_version(pkg.version)

    target = None
    for v in versions:
        vv = v.get("version")
        vvn = v.get("version_normalized")
        if isinstance(vv, str) and normalize_composer_version(vv) == want:
            target = v
            break
        if isinstance(vvn, str) and normalize_composer_version(vvn) == want:
            target = v
            break
    if not target:
        return None

    lic = target.get("license")
    if isinstance(lic, list):
        items = [x.strip() for x in lic if isinstance(x, str) and x.strip()]
        return combine_licenses(items)
    if isinstance(lic, str) and lic.strip():
        return normalize_spdx_expr(lic)
    return None


def detect_composer_license_from_sources(pkg: Package, sources_root: str) -> Optional[Tuple[str, str]]:
    root_dir = pkg_root_dir(sources_root, "composer", pkg)
    if not os.path.isdir(root_dir):
        return None

    composer_json = find_first_file(root_dir, "composer.json")
    if composer_json:
        try:
            with open(composer_json, "r", encoding="utf-8") as f:
                data = json.load(f)
            lic = data.get("license")
            if isinstance(lic, str) and lic.strip():
                return normalize_spdx_expr(lic), composer_json
            if isinstance(lic, list):
                items = [x.strip() for x in lic if isinstance(x, str) and x.strip()]
                if items:
                    return combine_licenses(items), composer_json
        except Exception:
            pass

    res = detect_license_from_sources_generic(pkg, sources_root)
    if res:
        lic_str, details = res
        return lic_str, details
    return None


def detect_cargo_license_from_registry(pkg: Package) -> Optional[str]:
    url = f"https://crates.io/api/v1/crates/{pkg.name}/{pkg.version}"
    data = http_get_json(url)
    if not data:
        return None
    vobj = data.get("version") or {}
    lic = vobj.get("license")
    if isinstance(lic, str) and lic.strip():
        return normalize_spdx_expr(lic)
    return None


def parse_cargo_toml_license(toml_bytes: bytes) -> str:
    if tomllib is not None:
        try:
            obj = tomllib.loads(toml_bytes.decode("utf-8", errors="ignore"))
            pkg = obj.get("package") or {}
            lic = pkg.get("license")
            if isinstance(lic, str) and lic.strip():
                return normalize_spdx_expr(lic)
        except Exception:
            pass

    text = toml_bytes.decode("utf-8", errors="ignore")
    m = re.search(r'(?m)^\s*license\s*=\s*"(.*?)"\s*$', text)
    if m:
        return normalize_spdx_expr(m.group(1))
    return ""


def detect_cargo_license_from_download(pkg: Package) -> Optional[str]:
    url = f"https://crates.io/api/v1/crates/{pkg.name}/{pkg.version}/download"
    blob = http_download_bytes(url, max_bytes=80 * 1024 * 1024, timeout=120)
    if not blob:
        return None
    try:
        tf = tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz")
    except Exception:
        return None

    cargo_toml_member = None
    try:
        for m in tf.getmembers():
            if m.isfile() and m.name.endswith("/Cargo.toml"):
                cargo_toml_member = m
                break
        if not cargo_toml_member:
            return None
        f = tf.extractfile(cargo_toml_member)
        if not f:
            return None
        content = f.read(512000)
        lic = parse_cargo_toml_license(content)
        return lic if lic else None
    finally:
        try:
            tf.close()
        except Exception:
            pass


TROVE_TO_SPDX = {
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: BSD License": "BSD",
    "License :: OSI Approved :: BSD 3-Clause \"New\" or \"Revised\" License": "BSD-3-Clause",
    "License :: OSI Approved :: BSD 2-Clause \"Simplified\" License": "BSD-2-Clause",
    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)": "GPL-3.0",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)": "GPL-2.0",
    "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0",
    "License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.0",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: Eclipse Public License 2.0 (EPL-2.0)": "EPL-2.0",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: Public Domain": "Unlicense",
}


def trove_classifiers_to_spdx(classifiers: List[str]) -> str:
    found: List[str] = []
    for c in classifiers:
        if not isinstance(c, str):
            continue
        if c.startswith("License ::"):
            spdx = TROVE_TO_SPDX.get(c)
            if spdx:
                found.append(spdx)
    return combine_licenses(found)


def detect_pypi_license_from_registry(pkg: Package) -> Optional[str]:
    url = f"https://pypi.org/pypi/{pkg.name}/{pkg.version}/json"
    data = http_get_json(url)
    if not data:
        return None
    info = data.get("info") or {}

    for k in ("license_expression", "license_expression_spdx", "license_expression_spdx_id"):
        v = info.get(k)
        if isinstance(v, str) and v.strip() and looks_like_spdx(v.strip()):
            return normalize_spdx_expr(v)

    lic_field = info.get("license")
    if isinstance(lic_field, str):
        lic_field = lic_field.strip()
        if looks_like_spdx(lic_field):
            return normalize_spdx_expr(lic_field)

    classifiers = info.get("classifiers") or []
    if isinstance(classifiers, list):
        lic = trove_classifiers_to_spdx(classifiers)
        if lic:
            return lic

    return None


def parse_core_metadata_for_license(meta_text: str) -> str:
    if not meta_text:
        return ""
    lines = meta_text.splitlines()

    lic_expr = ""
    classifiers: List[str] = []
    lic_plain = ""

    for line in lines:
        if line.lower().startswith("license-expression:"):
            val = line.split(":", 1)[1].strip()
            if val:
                lic_expr = val
        elif line.lower().startswith("license:"):
            val = line.split(":", 1)[1].strip()
            if val:
                lic_plain = val
        elif line.lower().startswith("classifier:"):
            val = line.split(":", 1)[1].strip()
            if val.startswith("License ::"):
                classifiers.append(val)

    if lic_expr and looks_like_spdx(lic_expr):
        return normalize_spdx_expr(lic_expr)

    if lic_plain and looks_like_spdx(lic_plain):
        return normalize_spdx_expr(lic_plain)

    lic = trove_classifiers_to_spdx(classifiers)
    return lic


def detect_pypi_license_from_sdist(pkg: Package) -> Optional[str]:
    url = f"https://pypi.org/pypi/{pkg.name}/{pkg.version}/json"
    data = http_get_json(url)
    if not data:
        return None
    urls = data.get("urls") or []
    sdist_url = None
    if isinstance(urls, list):
        for u in urls:
            if not isinstance(u, dict):
                continue
            if u.get("packagetype") == "sdist" and isinstance(u.get("url"), str):
                sdist_url = u["url"]
                break
    if not sdist_url:
        return None

    blob = http_download_bytes(sdist_url, max_bytes=120 * 1024 * 1024, timeout=180)
    if not blob:
        return None

    meta_text = ""
    if sdist_url.endswith((".tar.gz", ".tgz")):
        try:
            tf = tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz")
            try:
                for m in tf.getmembers():
                    if m.isfile() and (m.name.endswith("/PKG-INFO") or m.name.endswith("PKG-INFO")):
                        f = tf.extractfile(m)
                        if f:
                            meta_text = f.read(800000).decode("utf-8", errors="ignore")
                            break
                if not meta_text:
                    for m in tf.getmembers():
                        if m.isfile() and m.name.endswith("/METADATA") and ".dist-info/" in m.name:
                            f = tf.extractfile(m)
                            if f:
                                meta_text = f.read(800000).decode("utf-8", errors="ignore")
                                break
            finally:
                tf.close()
        except Exception:
            meta_text = ""
    elif sdist_url.endswith(".zip"):
        try:
            zf = zipfile.ZipFile(io.BytesIO(blob))
            try:
                names = zf.namelist()
                cand = [n for n in names if n.endswith("PKG-INFO")]
                if cand:
                    meta_text = zf.read(cand[0])[:800000].decode("utf-8", errors="ignore")
                if not meta_text:
                    cand = [n for n in names if n.endswith("METADATA") and ".dist-info/" in n]
                    if cand:
                        meta_text = zf.read(cand[0])[:800000].decode("utf-8", errors="ignore")
            finally:
                zf.close()
        except Exception:
            meta_text = ""

    lic = parse_core_metadata_for_license(meta_text)
    return lic if lic else None


def detect_npm_license_from_registry(pkg: Package) -> Optional[str]:
    name_enc = pkg.name.replace("/", "%2F")
    url = f"https://registry.npmjs.org/{name_enc}"
    data = http_get_json(url)
    if not data:
        return None
    versions = data.get("versions") or {}
    vobj = versions.get(pkg.version)
    if not isinstance(vobj, dict):
        return None
    lic = vobj.get("license")
    if isinstance(lic, str) and lic.strip():
        return normalize_spdx_expr(lic)
    if isinstance(lic, dict):
        t = lic.get("type")
        if isinstance(t, str) and t.strip():
            return normalize_spdx_expr(t)
    return None


def detect_nuget_license_from_registry(pkg: Package) -> Optional[str]:
    pid = pkg.name.lower()
    ver = pkg.version.lower()
    url = f"https://api.nuget.org/v3-flatcontainer/{pid}/{ver}/{pid}.nuspec"
    xml_text = http_get_text(url)
    if not xml_text:
        return None
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return None

    def strip_ns(tag: str) -> str:
        return tag.split("}", 1)[1] if "}" in tag else tag

    license_expr = None
    for el in root.iter():
        t = strip_ns(el.tag)
        if t == "license" and el.text:
            license_expr = el.text.strip()

    if license_expr:
        return normalize_spdx_expr(license_expr)
    return None


def maven_pom_url(group: str, artifact: str, version: str) -> str:
    gpath = group.replace(".", "/")
    return f"https://repo1.maven.org/maven2/{gpath}/{artifact}/{version}/{artifact}-{version}.pom"


def detect_maven_license_from_registry(pkg: Package) -> Optional[str]:
    if ":" not in pkg.name:
        return None
    group, artifact = pkg.name.split(":", 1)
    url = maven_pom_url(group, artifact, pkg.version)
    pom = http_get_text(url)
    if not pom:
        return None
    try:
        root = ET.fromstring(pom)
    except Exception:
        return None

    def strip_ns(tag: str) -> str:
        return tag.split("}", 1)[1] if "}" in tag else tag

    found: List[str] = []
    for licenses_el in root.iter():
        if strip_ns(licenses_el.tag) != "licenses":
            continue
        for lic_el in list(licenses_el):
            if strip_ns(lic_el.tag) != "license":
                continue
            lic_name = None
            for child in list(lic_el):
                if strip_ns(child.tag) == "name" and child.text:
                    lic_name = child.text.strip()
            if lic_name:
                n = lic_name.lower()
                if "apache" in n and "2" in n:
                    found.append("Apache-2.0")
                elif "mit" in n:
                    found.append("MIT")
                elif "bsd" in n and "3" in n:
                    found.append("BSD-3-Clause")
                elif "bsd" in n and "2" in n:
                    found.append("BSD-2-Clause")
                elif "mozilla" in n and "2" in n:
                    found.append("MPL-2.0")
                elif "eclipse public license" in n and "2" in n:
                    found.append("EPL-2.0")
                elif "gpl" in n and "3" in n:
                    found.append("GPL-3.0")
                elif "gpl" in n and "2" in n:
                    found.append("GPL-2.0")
                elif "lgpl" in n and "3" in n:
                    found.append("LGPL-3.0")
                elif "lgpl" in n and "2.1" in n:
                    found.append("LGPL-2.1")
                elif "isc" in n:
                    found.append("ISC")

    lic = combine_licenses(found)
    return lic if lic else None


def detect_license_for_package(pkg: Package, sources_root: str) -> Tuple[str, str, str]:
    if pkg.ecosystem == "composer":
        lic = detect_composer_license_from_registry(pkg)
        if lic:
            return lic, "registry", "packagist"

    elif pkg.ecosystem == "cargo":
        lic = detect_cargo_license_from_registry(pkg)
        if lic:
            return lic, "registry", "crates.io"
        lic2 = detect_cargo_license_from_download(pkg)
        if lic2:
            return lic2, "registry+download", "crates.io (Cargo.toml)"

    elif pkg.ecosystem == "pypi":
        lic = detect_pypi_license_from_registry(pkg)
        if lic:
            return lic, "registry", "pypi"
        lic2 = detect_pypi_license_from_sdist(pkg)
        if lic2:
            return lic2, "registry+download", "pypi (sdist metadata)"

    elif pkg.ecosystem == "npm":
        lic = detect_npm_license_from_registry(pkg)
        if lic:
            return lic, "registry", "npmjs"

    elif pkg.ecosystem == "nuget":
        lic = detect_nuget_license_from_registry(pkg)
        if lic:
            return lic, "registry", "nuget.org"

    elif pkg.ecosystem == "maven":
        lic = detect_maven_license_from_registry(pkg)
        if lic:
            return lic, "registry", "repo1.maven.org"

    if pkg.license_sbom:
        return normalize_spdx_expr(pkg.license_sbom), "sbom", ""

    if pkg.ecosystem == "composer":
        res = detect_composer_license_from_sources(pkg, sources_root)
        if res:
            lic_str, origin = res
            return lic_str, "sources", origin
        return "", "unknown", ""

    res = detect_license_from_sources_generic(pkg, sources_root)
    if res:
        lic_str, details = res
        return lic_str, "sources", details

    return "", "unknown", ""


def print_progress(index: int, total: int, pkg: Package) -> None:
    pct = int((index / total) * 100) if total > 0 else 100
    msg = f"[{pct:3d}%] ({index}/{total}) {pkg.ecosystem} {pkg.name} {pkg.version} ..."
    sys.stdout.write("\r" + msg[:180])
    sys.stdout.flush()


def write_xlsx(rows: List[Tuple[str, ...]], outpath: str) -> None:
    wb = Workbook()
    ws = wb.active
    ws.title = "Licenses"

    for row in rows:
        ws.append(row)

    for col in ws.columns:
        max_len = 0
        col_letter = col[0].column_letter
        for cell in col:
            value = "" if cell.value is None else str(cell.value)
            max_len = max(max_len, len(value))
        ws.column_dimensions[col_letter].width = min(max_len + 2, 120)

    wb.save(outpath)
    print(f"\n[OK] Wrote {len(rows) - 1} rows to {outpath}")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect licenses for packages listed in a CycloneDX SBOM produced by Trivy "
                    "using registry lookups first, then SBOM, then downloaded sources, and write ALL dependency paths."
    )
    parser.add_argument("sbom", help="Path to CycloneDX SBOM JSON generated by Trivy")
    parser.add_argument(
        "--sources-dir",
        default=None,
        help="Directory where sources are stored (already downloaded). Default: <sbom_dir>/sources",
    )
    parser.add_argument(
        "--ecosystems",
        default="pypi,npm,conan,go,cargo,maven,nuget,composer",
        help="Comma-separated list of ecosystems to include (default: %(default)s)",
    )
    parser.add_argument(
        "--xlsx-out",
        default=None,
        help="Path to XLSX file to write results to. Default: <sbom_dir>/licenses.xlsx",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=400,
        help="Max depth for path enumeration (default: %(default)s).",
    )
    parser.add_argument(
        "--max-paths-per-lib",
        type=int,
        default=2000,
        help="Safety limit: max number of paths to store per lib (default: %(default)s).",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)

    sbom_path = os.path.abspath(args.sbom)
    sbom_dir = os.path.dirname(sbom_path)

    sources_dir = args.sources_dir or os.path.join(sbom_dir, "sources")
    xlsx_out = args.xlsx_out or os.path.join(sbom_dir, "licenses.xlsx")

    ecosystems = [e.strip() for e in args.ecosystems.split(",") if e.strip()]
    print(f"SBOM: {sbom_path}")
    print(f"Sources dir (already downloaded): {sources_dir}")
    print(f"XLSX out: {xlsx_out}")
    print(f"Include ecosystems: {ecosystems}")

    sbom = load_sbom(sbom_path)
    components = sbom.get("components", [])
    deps = sbom.get("dependencies", [])
    print(f"Loaded SBOM with {len(components)} components and {len(deps)} dependency entries")

    graph, roots = build_cdx_dependency_graph(sbom)
    parents = build_reverse_deps(graph)
    label_map = build_ref_label_map(sbom)
    print(f"[info] CDX dependency graph nodes: {len(graph)}, roots: {len(roots)}")

    packages = extract_packages_from_sbom(sbom, include_ecosystems=ecosystems)

    header = ("ecosystem", "name", "version", "license", "source", "details", "dependency_paths")
    data_rows: List[Tuple[str, str, str, str, str, str, str]] = []

    total = len(packages)
    for idx, pkg in enumerate(packages, start=1):
        print_progress(idx, total, pkg)

        lic, src, details = detect_license_for_package(pkg, sources_root=sources_dir)

        dep_paths = all_paths_for_package(
            pkg=pkg,
            parents=parents,
            roots=roots,
            label_map=label_map,
            max_depth=args.max_depth,
            max_paths_per_lib=args.max_paths_per_lib,
        )

        data_rows.append((pkg.ecosystem, pkg.name, pkg.version, lic, src, details, dep_paths))

    print()

    def _sort_key(r: Tuple[str, str, str, str, str, str, str]):
        lic = (r[3] or "").strip()
        return (1 if lic == "" else 0, r[0], r[1], r[2])

    data_rows.sort(key=_sort_key)

    rows = [header] + data_rows
    write_xlsx(rows, xlsx_out)


if __name__ == "__main__":
    main()
