#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import dataclasses
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote as url_quote
from urllib.parse import unquote as url_unquote

import requests
import yaml


@dataclasses.dataclass(frozen=True)
class Package:
    ecosystem: str
    name: str
    version: str
    component_ref: str
    pkg_id: Optional[str] = None


DOWNLOADED_URLS: Dict[str, str] = {}
CLONED_NUGET_REPOS: Dict[str, str] = {}


MAVEN_TEST_ARTIFACT_RE = re.compile(
    r"""
    (^|[-_.])test(s)?($|[-_.])
  | (^|[-_.])it($|[-_.])
  | integration([-_.]?test(s)?)?
  | interop([-_.]?data)?([-_.]?test(s)?)?
  | java\d+([-_.]?test(s)?)?
    """,
    re.IGNORECASE | re.VERBOSE,
)


def is_maven_test_artifact(maven_name: str) -> bool:
    if not maven_name or ":" not in maven_name:
        return False
    _, artifact = maven_name.split(":", 1)
    return bool(MAVEN_TEST_ARTIFACT_RE.search(artifact))


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def make_safe_dir_name(s: str) -> str:
    s = (s or "").strip()
    s = s.replace("\\", "_").replace("/", "_")
    return re.sub(r"[^A-Za-z0-9_.@\-\+]+", "_", s)


def load_sbom(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def detect_ecosystem_from_trivy(result_type: str, purl: str) -> Optional[str]:
    result_type = (result_type or "").lower().strip()
    mapping_type = {
        "pip": "pypi",
        "python": "pypi",
        "npm": "npm",
        "yarn": "npm",
        "conan": "conan",
        "gomod": "go",
        "go": "go",
        "cargo": "cargo",
        "composer": "composer",
        "pom": "maven",
        "maven": "maven",
        "gradle": "maven",
        "nuget": "nuget",
        "bundler": None,
    }
    eco = mapping_type.get(result_type)
    if eco:
        return eco

    purl = (purl or "").lower()
    if purl.startswith("pkg:pypi/"):
        return "pypi"
    if purl.startswith("pkg:npm/"):
        return "npm"
    if purl.startswith("pkg:conan/"):
        return "conan"
    if purl.startswith("pkg:golang/") or purl.startswith("pkg:go/"):
        return "go"
    if purl.startswith("pkg:cargo/"):
        return "cargo"
    if purl.startswith("pkg:maven/"):
        return "maven"
    if purl.startswith("pkg:nuget/"):
        return "nuget"
    if purl.startswith("pkg:composer/"):
        return "composer"

    return None


def extract_packages_from_sbom(
    sbom: dict,
    include_ecosystems: Optional[Iterable[str]] = None,
) -> List[Package]:
    results = sbom.get("Results") or []
    include = set(include_ecosystems) if include_ecosystems is not None else None
    packages: Dict[Tuple[str, str, str], Package] = {}

    for res in results:
        res_type = res.get("Type") or ""
        pkgs = res.get("Packages") or []

        for pkg in pkgs:
            if not isinstance(pkg, dict):
                continue

            ident = pkg.get("Identifier") or {}
            purl = ident.get("PURL") or ""

            ecosystem = detect_ecosystem_from_trivy(res_type, purl)
            if not ecosystem:
                continue
            if include and ecosystem not in include:
                continue

            name: Optional[str] = None
            version: Optional[str] = None
            pkg_id = pkg.get("ID")

            if isinstance(purl, str) and purl.startswith("pkg:"):
                try:
                    _, after = purl.split("pkg:", 1)
                    _, tail = after.split("/", 1)
                except ValueError:
                    tail = ""
                tail = url_unquote(tail)

                if "@" in tail:
                    name_part, ver_part = tail.rsplit("@", 1)
                    version = ver_part

                    if ecosystem == "maven":
                        if "/" in name_part:
                            group, artifact = name_part.split("/", 1)
                            name = f"{group}:{artifact}"
                        else:
                            name = name_part
                    else:
                        name = name_part

            if not name:
                name = pkg.get("Name")
            if not version:
                version = pkg.get("Version")

            if not name or not version:
                continue

            if ecosystem == "maven" and is_maven_test_artifact(name):
                print(f"[SKIP][maven-test] {name}:{version} (ref={pkg.get('ID') or purl})")
                continue

            key = (ecosystem, name, version)
            if key not in packages:
                component_ref = pkg.get("ID") or purl or name
                packages[key] = Package(
                    ecosystem=ecosystem,
                    name=name,
                    version=version,
                    component_ref=component_ref,
                    pkg_id=pkg_id,
                )

    print(f"Found {len(packages)} unique (ecosystem, name, version) entries")
    return list(packages.values())


def maybe_extract_archive(file_path: str, dest_dir: Optional[str] = None) -> bool:
    ext = file_path.lower()
    fmt = None

    if ext.endswith((".zip", ".whl", ".jar", ".nupkg")):
        fmt = "zip"
    elif ext.endswith((".tar.gz", ".tgz")):
        fmt = "gztar"
    elif ext.endswith(".tar.bz2"):
        fmt = "bztar"
    elif ext.endswith(".tar.xz"):
        fmt = "xztar"
    elif ext.endswith(".tar"):
        fmt = "tar"
    elif ext.endswith(".crate"):
        fmt = "gztar"

    if fmt is None:
        try:
            with open(file_path, "rb") as f:
                header = f.read(4)
                if header.startswith(b"PK\x03\x04"):
                    fmt = "zip"
        except Exception as e:
            print(f" -> cannot inspect file header for {file_path}: {e}")
            return False

    if fmt is None:
        return False

    if dest_dir is None:
        dest_dir = os.path.join(os.path.dirname(file_path), "extracted")
    ensure_dir(dest_dir)

    try:
        print(f" -> unpacking {file_path} to {dest_dir} as {fmt}")
        shutil.unpack_archive(file_path, dest_dir, format=fmt)
        return True
    except Exception as e:
        print(f" -> failed to unpack {file_path}: {e}")
        return False


def download_url_to_file(url: str, dest_path: str) -> Tuple[bool, str]:
    ensure_dir(os.path.dirname(dest_path))

    if url in DOWNLOADED_URLS:
        original = DOWNLOADED_URLS[url]
        print(f" -> already downloaded {url}, reusing {original}")
        if os.path.abspath(original) != os.path.abspath(dest_path) and not os.path.exists(dest_path):
            try:
                os.link(original, dest_path)
                print(f" -> created hardlink {dest_path} -> {original}")
            except OSError:
                shutil.copy2(original, dest_path)
                print(f" -> copied existing file to {dest_path}")
        return False, original

    print(f" -> downloading {url}")
    resp = requests.get(url, stream=True, timeout=60)
    resp.raise_for_status()

    with open(dest_path, "wb") as f:
        for chunk in resp.iter_content(chunk_size=65536):
            if chunk:
                f.write(chunk)

    DOWNLOADED_URLS[url] = dest_path
    return True, dest_path


def pkg_root_dir(out_root: str, ecosystem: str, pkg: Package) -> str:
    safe_name = make_safe_dir_name(pkg.name)
    dirname = f"{safe_name}-{pkg.version}"
    return os.path.join(out_root, ecosystem, dirname)


def has_existing_sources(root_dir: str) -> bool:
    if not os.path.isdir(root_dir):
        return False
    try:
        with os.scandir(root_dir) as it:
            for _ in it:
                return True
    except OSError:
        return False
    return False


def download_pypi_source(pkg: Package, out_root: str) -> Tuple[bool, str, str]:
    base_url = "https://pypi.org/pypi"
    name = pkg.name
    version = pkg.version
    meta_url = f"{base_url}/{name}/{version}/json"
    print(f"[pypi] {name}=={version} - querying {meta_url}")

    dest_dir = pkg_root_dir(out_root, "pypi", pkg)
    if has_existing_sources(dest_dir):
        print(f"[pypi] {name}=={version} - sources already present in {dest_dir}, skip")
        return True, "already_present", ""

    try:
        resp = requests.get(meta_url, timeout=30)
        if resp.status_code != 200:
            msg = f"HTTP {resp.status_code} on metadata"
            print(f"[pypi] {name}=={version} - {msg}")
            return False, msg, meta_url
        data = resp.json()
    except Exception as e:
        msg = f"metadata_query_error: {e}"
        print(f"[pypi] {name}=={version} - {msg}")
        return False, msg, meta_url

    urls = data.get("urls") or []
    sdist = None
    wheel = None
    for u in urls:
        if u.get("packagetype") == "sdist" and not sdist:
            sdist = u
        if u.get("packagetype") == "bdist_wheel" and not wheel:
            wheel = u

    chosen = sdist or wheel
    if not chosen:
        msg = "no_sdist_or_wheel"
        print(f"[pypi] {name}=={version} - {msg}")
        return False, msg, meta_url

    file_url = chosen.get("url")
    filename = chosen.get("filename") or os.path.basename(file_url or "")
    if not file_url or not filename:
        msg = "invalid_file_metadata"
        print(f"[pypi] {name}=={version} - {msg}")
        return False, msg, meta_url

    ensure_dir(dest_dir)
    dest_path = os.path.join(dest_dir, filename)

    try:
        first, actual_path = download_url_to_file(file_url, dest_path)
        print(f"[pypi] {name}=={version} - downloaded to {actual_path}")
        if first:
            ok = maybe_extract_archive(actual_path, dest_dir=dest_dir)
            if ok:
                try:
                    os.remove(actual_path)
                    print(f"[pypi] {name}=={version} - removed archive after extract")
                except Exception as e:
                    print(f"[pypi] {name}=={version} - failed to remove archive: {e}")
        else:
            print(f"[pypi] {name}=={version} - reused cached archive, skip unpack")
        return has_existing_sources(dest_dir), "", file_url
    except Exception as e:
        msg = f"download_failed: {e}"
        print(f"[pypi] {name}=={version} - {msg}")
        return False, msg, file_url


def download_npm_source(pkg: Package, out_root: str) -> Tuple[bool, str, str]:
    name = pkg.name
    version = pkg.version
    url_name = "%40" + name[1:] if name.startswith("@") else name
    meta_url = f"https://registry.npmjs.org/{url_name}"
    print(f"[npm] {name}@{version} - querying {meta_url}")

    dest_dir = pkg_root_dir(out_root, "npm", pkg)
    if has_existing_sources(dest_dir):
        print(f"[npm] {name}@{version} - sources already present in {dest_dir}, skip")
        return True, "already_present", ""

    try:
        resp = requests.get(meta_url, timeout=30)
        if resp.status_code != 200:
            msg = f"HTTP {resp.status_code} on metadata"
            print(f"[npm] {name}@{version} - {msg}")
            return False, msg, meta_url
        data = resp.json()
    except Exception as e:
        msg = f"metadata_query_error: {e}"
        print(f"[npm] {name}@{version} - {msg}")
        return False, msg, meta_url

    versions = data.get("versions") or {}
    vinfo = versions.get(version)
    if not vinfo:
        msg = "version_not_found_in_metadata"
        print(f"[npm] {name}@{version} - {msg}")
        return False, msg, meta_url

    dist = vinfo.get("dist") or {}
    tarball = dist.get("tarball")
    if not tarball:
        msg = "no_dist_tarball"
        print(f"[npm] {name}@{version} - {msg}")
        return False, msg, meta_url

    filename = os.path.basename(tarball.split("?", 1)[0]) or f"{make_safe_dir_name(name)}-{version}.tgz"
    ensure_dir(dest_dir)
    dest_path = os.path.join(dest_dir, filename)

    try:
        first, actual_path = download_url_to_file(tarball, dest_path)
        print(f"[npm] {name}@{version} - downloaded to {actual_path}")
        if first:
            ok = maybe_extract_archive(actual_path, dest_dir=dest_dir)
            if ok:
                try:
                    os.remove(actual_path)
                    print(f"[npm] {name}@{version} - removed archive after extract")
                except Exception as e:
                    print(f"[npm] {name}@{version} - failed to remove archive: {e}")
        else:
            print(f"[npm] {name}@{version} - reused cached archive, skip unpack")
        return has_existing_sources(dest_dir), "", tarball
    except Exception as e:
        msg = f"download_failed: {e}"
        print(f"[npm] {name}@{version} - {msg}")
        return False, msg, tarball


def download_go_source(pkg: Package, out_root: str) -> Tuple[bool, str, str]:
    module = pkg.name
    version = pkg.version

    dest_dir = pkg_root_dir(out_root, "go", pkg)
    if has_existing_sources(dest_dir):
        print(f"[go] {module}@{version} - sources already present in {dest_dir}, skip")
        return True, "already_present", ""

    module_path = url_quote(module, safe="/")
    url = f"https://proxy.golang.org/{module_path}/@v/{version}.zip"
    print(f"[go] {module}@{version} - downloading {url}")

    ensure_dir(dest_dir)
    filename = f"{make_safe_dir_name(module)}-{version}.zip"
    dest_path = os.path.join(dest_dir, filename)

    try:
        first, actual_path = download_url_to_file(url, dest_path)
        print(f"[go] {module}@{version} - downloaded to {actual_path}")
        if first:
            ok = maybe_extract_archive(actual_path, dest_dir=dest_dir)
            if ok:
                try:
                    os.remove(actual_path)
                    print(f"[go] {module}@{version} - removed archive after extract")
                except Exception as e:
                    print(f"[go] {module}@{version} - failed to remove archive: {e}")
        else:
            print(f"[go] {module}@{version} - reused cached archive, skip unpack")
        return has_existing_sources(dest_dir), "", url
    except Exception as e:
        msg = f"download_failed: {e}"
        print(f"[go] {module}@{version} - {msg}")
        return False, msg, url


def download_cargo_source(pkg: Package, out_root: str) -> Tuple[bool, str, str]:
    name = pkg.name
    version = pkg.version
    url = f"https://crates.io/api/v1/crates/{name}/{version}/download"
    print(f"[cargo] {name}@{version} - downloading {url}")

    dest_dir = pkg_root_dir(out_root, "cargo", pkg)
    if has_existing_sources(dest_dir):
        print(f"[cargo] {name}@{version} - sources already present in {dest_dir}, skip")
        return True, "already_present", ""

    ensure_dir(dest_dir)
    filename = f"{make_safe_dir_name(name)}-{version}.crate"
    dest_path = os.path.join(dest_dir, filename)

    try:
        first, actual_path = download_url_to_file(url, dest_path)
        print(f"[cargo] {name}@{version} - downloaded to {actual_path}")
        if first:
            ok = maybe_extract_archive(actual_path, dest_dir=dest_dir)
            if ok:
                try:
                    os.remove(actual_path)
                    print(f"[cargo] {name}@{version} - removed archive after extract")
                except Exception as e:
                    print(f"[cargo] {name}@{version} - failed to remove archive: {e}")
        else:
            print(f"[cargo] {name}@{version} - reused cached archive, skip unpack")
        return has_existing_sources(dest_dir), "", url
    except Exception as e:
        msg = f"download_failed: {e}"
        print(f"[cargo] {name}@{version} - {msg}")
        return False, msg, url


def download_maven_source(pkg: Package, out_root: str) -> Tuple[bool, str, str]:
    name = pkg.name
    version = pkg.version

    dest_dir = pkg_root_dir(out_root, "maven", pkg)
    if has_existing_sources(dest_dir):
        print(f"[maven] {name}:{version} - sources already present in {dest_dir}, skip")
        return True, "already_present", ""

    if ":" not in name:
        msg = "invalid_maven_name_expected_group_artifact"
        print(f"[maven] {name}:{version} - {msg}")
        return False, msg, ""

    group, artifact = name.split(":", 1)
    group_path = group.replace(".", "/")
    base = f"https://repo1.maven.org/maven2/{group_path}/{artifact}/{version}"

    candidates = [
        f"{base}/{artifact}-{version}-sources.jar",
        f"{base}/{artifact}-{version}-source.jar",
        f"{base}/{artifact}-{version}.jar",
    ]

    ensure_dir(dest_dir)
    last_url = ""

    for url in candidates:
        last_url = url
        filename = os.path.basename(url)
        dest_path = os.path.join(dest_dir, filename)

        if os.path.exists(dest_path):
            print(f"[maven] {name}:{version} - {filename} already exists")
            ok = maybe_extract_archive(dest_path, dest_dir=dest_dir)
            if ok:
                try:
                    os.remove(dest_path)
                    print(f"[maven] {name}:{version} - removed archive after extract")
                except Exception as e:
                    print(f"[maven] {name}:{version} - failed to remove archive: {e}")
            return has_existing_sources(dest_dir), "", url

        print(f"[maven] {name}:{version} - trying {url}")
        try:
            first, actual_path = download_url_to_file(url, dest_path)
            print(f"[maven] {name}:{version} - downloaded to {actual_path}")
            if first:
                ok = maybe_extract_archive(actual_path, dest_dir=dest_dir)
                if ok:
                    try:
                        os.remove(actual_path)
                        print(f"[maven] {name}:{version} - removed archive after extract")
                    except Exception as e:
                        print(f"[maven] {name}:{version} - failed to remove archive: {e}")
            else:
                print(f"[maven] {name}:{version} - reused cached archive, skip unpack")
            return has_existing_sources(dest_dir), "", url
        except Exception as e:
            print(f"[maven] {name}:{version} - failed {url}: {e}")

    msg = "no_suitable_artifact_found"
    print(f"[maven] {name}:{version} - {msg}")
    return has_existing_sources(dest_dir), msg, last_url


def _fetch_json_safe(url: str) -> Optional[dict]:
    if not isinstance(url, str):
        return None
    url = url.strip()
    if not url:
        return None
    try:
        r = requests.get(url, timeout=30)
        if r.status_code != 200:
            return None
        data = r.json()
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _merge_dicts_shallow(base: dict, extra: dict) -> dict:
    if not isinstance(base, dict):
        base = {}
    if not isinstance(extra, dict):
        return dict(base)
    merged = dict(extra)
    merged.update(base)
    return merged


def _extract_catalog_entry(data: dict) -> dict:
    if not isinstance(data, dict):
        return {}

    if "id" in data and "version" in data and (
        "repository" in data or "projectUrl" in data or "packageContent" in data
    ):
        return data

    def resolve_ce(ce) -> dict:
        if isinstance(ce, dict):
            ce_url = ce.get("@id")
            if isinstance(ce_url, str):
                sub = _fetch_json_safe(ce_url)
                if isinstance(sub, dict):
                    return _merge_dicts_shallow(ce, sub)
            return ce

        if isinstance(ce, str):
            sub = _fetch_json_safe(ce)
            if isinstance(sub, dict):
                return sub

        return {}

    ce = data.get("catalogEntry")
    if ce is not None:
        resolved = resolve_ce(ce)
        if resolved:
            return resolved

    items = data.get("items") or []
    if isinstance(items, list):
        for outer in items:
            if not isinstance(outer, dict):
                continue
            inner_items = outer.get("items") or []
            if not isinstance(inner_items, list):
                continue
            for inner in inner_items:
                if not isinstance(inner, dict):
                    continue
                ce2 = inner.get("catalogEntry")
                if ce2 is None:
                    continue
                resolved = resolve_ce(ce2)
                if resolved:
                    return resolved

    return {}


def looks_like_git_repo(url: str) -> bool:
    if not isinstance(url, str):
        return False
    normalized = url.strip().lower()
    if not normalized:
        return False
    if normalized.startswith("git@"):
        return True
    if normalized.endswith(".git"):
        return True
    if "github.com/" in normalized or "gitlab.com/" in normalized or "bitbucket.org/" in normalized:
        return True
    return False


def download_nuget_source(pkg: Package, out_root: str) -> Tuple[bool, str, str]:
    name = pkg.name
    version = pkg.version

    dest_dir = pkg_root_dir(out_root, "nuget", pkg)
    print(f"= nuget :: {name} :: {version} (ref={pkg.component_ref}) ===")
    print(f"[nuget-git] target dir: {dest_dir}")

    if os.path.isdir(dest_dir) and os.listdir(dest_dir):
        print(f"[nuget-git] sources already present in {dest_dir}, skip")
        return True, "already_present", ""

    lower_id = name.lower()
    reg_url = f"https://api.nuget.org/v3/registration5-gz-semver2/{lower_id}/{version}.json"
    print(f"[nuget-git] query {reg_url}")

    try:
        r = requests.get(reg_url, timeout=30)
        if r.status_code != 200:
            msg = f"registry_http_{r.status_code}"
            print(f"[nuget-git] {msg}")
            return False, msg, reg_url
        data = r.json()
        if not isinstance(data, dict):
            msg = "registry_response_not_dict"
            print(f"[nuget-git] {msg}")
            return False, msg, reg_url
    except Exception as e:
        msg = f"registry_query_error: {e}"
        print(f"[nuget-git] {msg}")
        return False, msg, reg_url

    catalog = _extract_catalog_entry(data)
    if not isinstance(catalog, dict) or not catalog:
        msg = "no_catalogEntry_dict_in_registry_response"
        print(f"[nuget-git] {msg}")
        return False, msg, reg_url

    repo_url = ""
    repo_info = catalog.get("repository")
    if isinstance(repo_info, dict):
        val = repo_info.get("url")
        if isinstance(val, str):
            repo_url = val.strip()
    elif isinstance(repo_info, str):
        repo_url = repo_info.strip()

    project_url = catalog.get("projectUrl")
    project_url = project_url.strip() if isinstance(project_url, str) else ""

    git_url = None
    for candidate in (repo_url, project_url):
        if isinstance(candidate, str) and candidate.startswith(("http://", "https://", "git@")):
            git_url = candidate.strip()
            break

    if not git_url:
        msg = "no_repository_or_projectUrl_in_catalogEntry"
        print(f"[nuget-git] {msg}")
        return False, msg, ""

    print(f"[nuget-git] repository/project URL: {git_url}")
    normalized = git_url.rstrip("/").lower()

    if any(s in normalized for s in ("dotnet.microsoft.com", "dot.net", "asp.net")):
        msg = "dotnet_marketing_site_skip_per_policy"
        print(f"[nuget-git] {msg}, not cloning {git_url}")
        return True, msg, git_url

    if normalized.startswith("https://github.com/dotnet/runtime") or normalized.startswith(
        "https://github.com/dotnet/aspnetcore"
    ):
        msg = "dotnet_monorepo_skip_per_policy"
        print(f"[nuget-git] {msg}, not cloning {git_url}")
        return True, msg, git_url

    if not looks_like_git_repo(git_url):
        msg = "non_git_repository_url_in_nuget_metadata_skip_per_policy"
        print(f"[nuget-git] {msg}, not cloning {git_url}")
        return True, msg, git_url

    prev = CLONED_NUGET_REPOS.get(normalized)
    if prev:
        msg = f"duplicate_repository_skip_per_policy (already cloned for {prev})"
        print(f"[nuget-git] {msg}, not cloning {git_url}")
        return True, msg, git_url

    CLONED_NUGET_REPOS[normalized] = f"{name}@{version}"
    os.makedirs(dest_dir, exist_ok=True)

    print(f"[nuget-git] cloning into {dest_dir}")
    clone_cmd = ["git", "clone", "--depth", "1", git_url, dest_dir]
    res = subprocess.run(clone_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    if res.returncode != 0:
        msg = f"git_clone_failed: {res.stdout.strip()[:4000]}"
        print("[nuget-git] git clone failed:")
        print(res.stdout)
        return False, msg, git_url

    print("[nuget-git] clone OK")

    tag_candidates = [
        f"v{version}",
        f"V{version}",
        version,
        f"{name}-{version}",
        f"{name.lower()}-{version}",
        f"{name}-V{version}",
        f"{name.lower()}-V{version}",
    ]

    def try_checkout_tag(tag: str) -> Tuple[bool, str]:
        rc = subprocess.run(
            ["git", "-C", dest_dir, "checkout", tag],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if rc.returncode == 0:
            return True, rc.stdout

        fetch = subprocess.run(
            ["git", "-C", dest_dir, "fetch", "--depth", "1", "origin", "tag", tag],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        rc2 = subprocess.run(
            ["git", "-C", dest_dir, "checkout", tag],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if rc2.returncode == 0:
            return True, rc2.stdout

        out = (rc.stdout or "") + "\n--- fetch ---\n" + (fetch.stdout or "") + "\n--- checkout2 ---\n" + (rc2.stdout or "")
        return False, out.strip()

    last_err = ""
    for tag in tag_candidates:
        print(f"[nuget-git] trying tag {tag}")
        ok2, out = try_checkout_tag(tag)
        if ok2:
            print(f"[nuget-git] checked out tag {tag}")
            last_err = ""
            break
        last_err = out[:4000]
    else:
        if last_err:
            print("[nuget-git] no matching tag found, staying on default branch " f"(last error: {last_err[:4000]})")
        else:
            print("[nuget-git] no matching tag found, staying on default branch")

    return True, "", git_url


def download_composer_source(pkg: Package, out_root: str) -> Tuple[bool, str, str]:
    full_name = pkg.name
    version = pkg.version

    dest_dir = pkg_root_dir(out_root, "composer", pkg)
    if has_existing_sources(dest_dir):
        print(f"[composer] {full_name}@{version} - sources already present in {dest_dir}, skip")
        return True, "already_present", ""

    if "/" not in full_name:
        msg = "invalid_composer_name_expected_vendor_package"
        print(f"[composer] {full_name}@{version} - {msg}")
        return False, msg, ""

    vendor, package = full_name.split("/", 1)
    meta_url = f"https://repo.packagist.org/p2/{vendor}/{package}.json"
    print(f"[composer] {full_name}@{version} - querying {meta_url}")

    try:
        resp = requests.get(meta_url, timeout=30)
        if resp.status_code != 200:
            msg = f"HTTP {resp.status_code} on metadata"
            print(f"[composer] {full_name}@{version} - {msg}")
            return False, msg, meta_url
        data = resp.json()
    except Exception as e:
        msg = f"metadata_query_error: {e}"
        print(f"[composer] {full_name}@{version} - {msg}")
        return False, msg, meta_url

    packages = data.get("packages", {}).get(full_name) or []
    vinfo = None
    for p in packages:
        if p.get("version") == version or p.get("version_normalized") == version:
            vinfo = p
            break

    if not vinfo:
        msg = "version_not_found_in_metadata"
        print(f"[composer] {full_name}@{version} - {msg}")
        return False, msg, meta_url

    dist = vinfo.get("dist") or {}
    url = dist.get("url")
    if not url:
        msg = "no_dist_url_in_metadata"
        print(f"[composer] {full_name}@{version} - {msg}")
        return False, msg, meta_url

    filename = os.path.basename(url.split("?", 1)[0]) or f"{vendor}-{package}-{version}.zip"
    ensure_dir(dest_dir)
    dest_path = os.path.join(dest_dir, filename)

    try:
        print(f"[composer] {full_name}@{version} - downloading {url}")
        first, actual_path = download_url_to_file(url, dest_path)
        print(f"[composer] {full_name}@{version} - downloaded to {actual_path}")
        if first:
            ok = maybe_extract_archive(actual_path, dest_dir=dest_dir)
            if ok:
                try:
                    os.remove(actual_path)
                    print(f"[composer] {full_name}@{version} - removed archive after extract")
                except Exception as e:
                    print(f"[composer] {full_name}@{version} - failed to remove archive: {e}")
        else:
            print(f"[composer] {full_name}@{version} - reused cached archive, skip unpack")
        return has_existing_sources(dest_dir), "", url
    except Exception as e:
        msg = f"download_failed: {e}"
        print(f"[composer] {full_name}@{version} - {msg}")
        return False, msg, url


def extract_source_urls_from_conandata(conandata: dict, version: str) -> List[str]:
    sources = conandata.get("sources") or {}
    node = sources.get(str(version))
    urls: List[str] = []

    def collect(n):
        if isinstance(n, dict):
            if "url" in n:
                u = n["url"]
                if isinstance(u, str):
                    urls.append(u)
                elif isinstance(u, list):
                    urls.extend([x for x in u if isinstance(x, str)])
            for v in n.values():
                collect(v)
        elif isinstance(n, list):
            for v in n:
                collect(v)

    if node is not None:
        collect(node)

    return sorted(set(urls))


def download_conan_source(pkg: Package, out_root: str, conan_remote: str) -> Tuple[bool, str, str]:
    name = pkg.name
    version = pkg.version
    pkg_ref = f"{name}/{version}"

    dest_dir = pkg_root_dir(out_root, "conan", pkg)
    if has_existing_sources(dest_dir):
        print(f"[conan] {pkg_ref} - sources already present in {dest_dir}, skip")
        return True, "already_present", ""

    print(f"[conan] {pkg_ref} - download recipe from remote '{conan_remote}'")
    try:
        subprocess.run(
            ["conan", "download", pkg_ref, "-r", conan_remote, "--only-recipe"],
            check=True,
        )
    except subprocess.CalledProcessError as e:
        msg = f"conan_download_failed: {e}"
        print(f"[conan] {pkg_ref} - 'conan download' failed: {e}")
        return False, msg, ""

    ensure_dir(dest_dir)
    source_copied = False

    for folder_kind in ("source", "export_source"):
        try:
            result = subprocess.run(
                ["conan", "cache", "path", pkg_ref, f"--folder={folder_kind}"],
                check=True,
                capture_output=True,
                text=True,
            )
            candidate = result.stdout.strip()
            if candidate and os.path.isdir(candidate) and os.listdir(candidate):
                print(f"[conan] {pkg_ref} - using {folder_kind} folder: {candidate}")
                for entry in os.listdir(candidate):
                    src_path = os.path.join(candidate, entry)
                    dst_path = os.path.join(dest_dir, entry)
                    if os.path.isdir(src_path):
                        shutil.copytree(src_path, dst_path, dirs_exist_ok=True)
                    else:
                        shutil.copy2(src_path, dst_path)
                source_copied = True
                break
        except subprocess.CalledProcessError:
            continue

    try:
        result = subprocess.run(
            ["conan", "cache", "path", pkg_ref],
            check=True,
            capture_output=True,
            text=True,
        )
        export_dir = result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"[conan] {pkg_ref} - 'conan cache path' (export) failed: {e}")
        export_dir = ""

    urls: List[str] = []
    conandata_path = os.path.join(export_dir, "conandata.yml") if export_dir else ""
    if os.path.isfile(conandata_path):
        try:
            with open(conandata_path, "r", encoding="utf-8") as f:
                conandata = yaml.safe_load(f) or {}
            urls = extract_source_urls_from_conandata(conandata, version)
        except Exception as e:
            print(f"[conan] {pkg_ref} - failed to parse conandata.yml: {e}")

    last_url = ""
    if not urls and not source_copied:
        msg = f"no_sources_and_no_urls_in_conandata_for_{version}"
        print(f"[conan] {pkg_ref} - no source/export_source content and no URLs in conandata.yml for version {version}")
        return has_existing_sources(dest_dir), msg, ""

    for url in urls:
        last_url = url
        filename = os.path.basename(url.split("?", 1)[0]) or f"{make_safe_dir_name(name)}-{version}.tar"
        dest_path = os.path.join(dest_dir, filename)

        if os.path.exists(dest_path):
            print(f"[conan] {pkg_ref} - {filename} already exists")
            ok = maybe_extract_archive(dest_path, dest_dir=dest_dir)
            if ok:
                try:
                    os.remove(dest_path)
                    print(f"[conan] {pkg_ref} - removed archive after extract")
                except Exception as e:
                    print(f"[conan] {pkg_ref} - failed to remove archive: {e}")
            continue

        try:
            print(f"[conan] {pkg_ref} - downloading upstream source {url}")
            first, actual_path = download_url_to_file(url, dest_path)
            print(f"[conan] {pkg_ref} - downloaded to {actual_path}")
            if first:
                ok = maybe_extract_archive(actual_path, dest_dir=dest_dir)
                if ok:
                    try:
                        os.remove(actual_path)
                        print(f"[conan] {pkg_ref} - removed archive after extract")
                    except Exception as e:
                        print(f"[conan] {pkg_ref} - failed to remove archive: {e}")
            else:
                print(f"[conan] {pkg_ref} - reused cached archive, skip unpack")
        except Exception as e:
            print(f"[conan] {pkg_ref} - upstream download failed ({url}): {e}")

    if source_copied:
        print(f"[conan] {pkg_ref} - local conan cache sources copied to {dest_dir}")

    return has_existing_sources(dest_dir), "", last_url


def download_sources(
    packages: List[Package],
    out_root: str,
    conan_remote: str,
    dry_run: bool = False,
) -> None:
    print(f"\nWill download sources for {len(packages)} packages")
    ensure_dir(out_root)

    failures: List[Dict[str, str]] = []
    successes: List[Dict[str, str]] = []

    for pkg in packages:
        print(f"\n=== {pkg.ecosystem} :: {pkg.name} :: {pkg.version} (ref={pkg.component_ref}) ===")

        if dry_run:
            print(" [dry-run] skip actual download")
            continue

        ok = False
        reason = ""
        primary_url = ""

        if pkg.ecosystem == "pypi":
            ok, reason, primary_url = download_pypi_source(pkg, out_root)
        elif pkg.ecosystem == "npm":
            ok, reason, primary_url = download_npm_source(pkg, out_root)
        elif pkg.ecosystem == "conan":
            ok, reason, primary_url = download_conan_source(pkg, out_root, conan_remote)
        elif pkg.ecosystem == "go":
            ok, reason, primary_url = download_go_source(pkg, out_root)
        elif pkg.ecosystem == "cargo":
            ok, reason, primary_url = download_cargo_source(pkg, out_root)
        elif pkg.ecosystem == "maven":
            ok, reason, primary_url = download_maven_source(pkg, out_root)
        elif pkg.ecosystem == "nuget":
            ok, reason, primary_url = download_nuget_source(pkg, out_root)
        elif pkg.ecosystem == "composer":
            ok, reason, primary_url = download_composer_source(pkg, out_root)
        else:
            reason = f"unsupported_ecosystem_{pkg.ecosystem}"
            print(f"[warn] unsupported ecosystem: {pkg.ecosystem}, skip")

        record = {
            "ecosystem": pkg.ecosystem,
            "name": pkg.name,
            "version": pkg.version,
            "component_ref": pkg.component_ref,
            "primary_url": primary_url,
            "reason": reason,
        }

        if (reason or "").endswith("_skip_per_policy") or "_skip_per_policy" in (reason or ""):
            print(f"[info] skip-per-policy: {reason}")
            successes.append(record)
            continue

        if ok:
            successes.append(record)
        else:
            failures.append(record)

    if successes and not dry_run:
        downloads_log_path = os.path.join(out_root, "sources_downloads.csv")
        try:
            with open(downloads_log_path, "w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=["ecosystem", "name", "version", "component_ref", "primary_url", "reason"],
                )
                writer.writeheader()
                for row in successes:
                    writer.writerow(row)
            print(f"\n[ok] Logged {len(successes)} processed packages to: {downloads_log_path}")
        except Exception as e:
            print(f"\n[ERR] failed to write sources_downloads.csv: {e}")

    if failures and not dry_run:
        log_path = os.path.join(out_root, "failed_downloads.csv")
        try:
            with open(log_path, "w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=["ecosystem", "name", "version", "component_ref", "primary_url", "reason"],
                )
                writer.writeheader()
                for row in failures:
                    writer.writerow(row)
            print(f"\n[warn] Failed to download sources for {len(failures)} packages. See CSV: {log_path}")
        except Exception as e:
            print(f"\n[ERR] failed to write failures CSV: {e}")
    else:
        print("\n[ok] All downloads finished without recorded failures (or dry-run mode).")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Download sources for packages listed in a Trivy JSON report")
    parser.add_argument("sbom", help="Path to Trivy JSON (trivy fs . -f json -o trivy.json)")
    parser.add_argument("--out-dir", default="sources", help="Directory where sources will be stored")
    parser.add_argument("--ecosystems", default="pypi,npm,conan,go,cargo,maven,nuget,composer")
    parser.add_argument("--conan-remote", default="conancenter")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)

    ecosystems = [e.strip() for e in args.ecosystems.split(",") if e.strip()]
    print(f"Include ecosystems: {ecosystems}")

    sbom = load_sbom(args.sbom)
    results = sbom.get("Results") or []
    pkg_count = sum(len(r.get("Packages") or []) for r in results)
    print(f"Loaded Trivy JSON with {len(results)} result entries and {pkg_count} package entries")

    packages = extract_packages_from_sbom(sbom, include_ecosystems=ecosystems)

    download_sources(
        packages=packages,
        out_root=args.out_dir,
        conan_remote=args.conan_remote,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
