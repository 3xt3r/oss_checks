#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import csv
import json
import re
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import urlsplit, urlunsplit


TOXIC_REPOS_RAW_URL = (
    "https://raw.githubusercontent.com/toxic-repos/toxic-repos/main/data/csv/toxic-repos.csv"
)

CACHE_DIR_NAME = "_toxic_repos_cache"
CACHE_FILE = "toxic-repos.csv"
META_FILE = "toxic-repos.meta.json"
CACHE_TTL_SECONDS = 24 * 60 * 60


def ensure_toxic_db_fresh(*, jobs_dir: Path) -> Tuple[Path, Dict[str, Any]]:
    cache_dir = jobs_dir / CACHE_DIR_NAME
    cache_dir.mkdir(parents=True, exist_ok=True)

    csv_path = cache_dir / CACHE_FILE
    meta_path = cache_dir / META_FILE

    now = time.time()

    if csv_path.is_file() and meta_path.is_file():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            downloaded_at = float(meta.get("downloaded_at", 0))
            if now - downloaded_at < CACHE_TTL_SECONDS:
                return csv_path, meta
        except Exception:
            pass

    req = urllib.request.Request(
        TOXIC_REPOS_RAW_URL,
        headers={"User-Agent": "sbom-portal/1.0"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        csv_path.write_bytes(r.read())

    meta = {
        "downloaded_at": now,
        "downloaded_at_iso": datetime.now(timezone.utc).isoformat(),
        "source": TOXIC_REPOS_RAW_URL,
        "ttl_seconds": CACHE_TTL_SECONDS,
    }
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    return csv_path, meta


def normalize_repo_slug(inp: str) -> str:
    s = (inp or "").strip()

    m = re.search(r"git@github\.com:([^/]+/[^/\s]+?)(?:\.git)?$", s, flags=re.IGNORECASE)
    if m:
        slug = m.group(1).strip()
        return slug[:-4] if slug.lower().endswith(".git") else slug

    m = re.search(r"github\.com/([^/]+/[^/\s]+?)(?:\.git)?(?:/)?$", s, flags=re.IGNORECASE)
    if m:
        slug = m.group(1).strip()
        return slug[:-4] if slug.lower().endswith(".git") else slug

    m = re.fullmatch(r"([^/\s]+)/([^/\s]+)", s)
    if m:
        slug = f"{m.group(1)}/{m.group(2)}"
        return slug[:-4] if slug.lower().endswith(".git") else slug

    return ""


def extract_repo_slug_from_github_url(url: str) -> str:
    s = (url or "").strip()
    m = re.search(r"github\.com/([^/\s]+)/([^/\s#?]+)", s, flags=re.IGNORECASE)
    if not m:
        return ""
    owner = (m.group(1) or "").strip()
    repo = (m.group(2) or "").strip()
    if repo.lower().endswith(".git"):
        repo = repo[:-4]
    return f"{owner}/{repo}" if owner and repo else ""


def normalize_url(u: str) -> str:
    s = (u or "").strip()
    if not s:
        return ""

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", s):
        s = "https://" + s

    p = urlsplit(s)
    scheme = (p.scheme or "https").lower()
    host = (p.hostname or "").lower()
    if not host:
        return ""

    path = p.path or "/"
    path = re.sub(r"/{2,}", "/", path)
    if path != "/" and path.endswith("/"):
        path = path[:-1]

    return urlunsplit((scheme, host, path, "", ""))


def url_host(u: str) -> str:
    nu = normalize_url(u)
    if not nu:
        return ""
    return (urlsplit(nu).hostname or "").lower()


def url_domain_naive(host: str) -> str:
    h = (host or "").lower().strip().strip(".")
    if not h:
        return ""
    parts = h.split(".")
    if len(parts) <= 2:
        return h
    return ".".join(parts[-2:])


def parse_purl(inp: str) -> Dict[str, str]:
    s = (inp or "").strip()
    m = re.match(r"^pkg:([^/]+)/([^@?#]+)(?:@([^?#]+))?(?:\?[^#]+)?(?:#.+)?$", s, flags=re.IGNORECASE)
    if not m:
        return {}
    ptype = (m.group(1) or "").strip().lower()
    name = (m.group(2) or "").strip().lower()
    version = (m.group(3) or "").strip()
    return {"type": ptype, "name": name, "version": version}


def build_token_regex(token: str) -> re.Pattern:
    t = (token or "").strip().lower()
    if not t:
        return re.compile(r"a^")
    return re.compile(rf"(?<![a-z0-9]){re.escape(t)}(?![a-z0-9])", re.IGNORECASE)


def build_indicators_from_input(inp: str, kind: str) -> Dict[str, Any]:
    s = (inp or "").strip()
    k = (kind or "").strip().lower()

    if not k:
        sl = s.lower()
        if sl.startswith("pkg:"):
            k = "pkg"
        elif "github.com" in sl or re.fullmatch(r"[^/\s]+/[^/\s]+", s):
            k = "git"
        elif "://" in s or s.startswith("www."):
            k = "wget"
        else:
            k = "name"

    out: Dict[str, Any] = {
        "input": s,
        "kind": k,
        "github_slug": "",
        "url_norm": "",
        "url_host": "",
        "url_domain": "",
        "purl": {},
        "name_token": "",
    }

    if not s:
        return out

    if k == "pkg" or s.lower().startswith("pkg:"):
        p = parse_purl(s)
        out["purl"] = p
        if p.get("name"):
            out["name_token"] = p["name"]
        return out

    slug = normalize_repo_slug(s)
    if slug:
        out["github_slug"] = slug
        out["name_token"] = slug.split("/", 1)[-1].lower()
        return out

    if "://" in s or s.startswith("www.") or re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/|$)", s):
        nu = normalize_url(s)
        out["url_norm"] = nu
        h = url_host(nu)
        out["url_host"] = h
        out["url_domain"] = url_domain_naive(h)
        if out["url_domain"]:
            out["name_token"] = out["url_domain"].split(".")[0]
        return out

    out["name_token"] = s.lower()
    return out


def build_indicators_from_row(row: Dict[str, Any]) -> Dict[str, Any]:
    fields = {
        "name": str(row.get("name") or "").strip(),
        "commit_link": str(row.get("commit_link") or "").strip(),
        "purl_link": str(row.get("PURL-link") or "").strip(),
        "purl": str(row.get("PURL") or "").strip(),
        "description": str(row.get("description") or "").strip(),
        "problem_type": str(row.get("problem_type") or "").strip(),
    }

    github_slug = ""
    for v in (fields["commit_link"], fields["name"], fields["purl_link"]):
        gs = normalize_repo_slug(v) or extract_repo_slug_from_github_url(v)
        if gs:
            github_slug = gs
            break

    url_candidates = [fields["commit_link"], fields["purl_link"], fields["name"]]
    url_norm = ""
    host = ""
    domain = ""
    for u in url_candidates:
        nu = normalize_url(u)
        if nu:
            url_norm = nu
            host = url_host(nu)
            domain = url_domain_naive(host)
            break

    p = parse_purl(fields["purl"]) if fields["purl"].lower().startswith("pkg:") else {}

    if github_slug:
        token = github_slug.split("/", 1)[-1].lower()
    elif p.get("name"):
        token = str(p["name"]).lower()
    else:
        token = fields["name"].strip().lower()

    return {
        "fields": fields,
        "github_slug": github_slug,
        "url_norm": url_norm,
        "url_host": host,
        "url_domain": domain,
        "purl": p,
        "name_token": token,
    }


def match_input_to_row(inp_ind: Dict[str, Any], row_ind: Dict[str, Any]) -> Tuple[bool, str]:
    a = (inp_ind.get("github_slug") or "").strip().lower()
    b = (row_ind.get("github_slug") or "").strip().lower()
    if a and b and a == b:
        return True, "github_slug"

    inu = (inp_ind.get("url_norm") or "").strip().lower()
    rnu = (row_ind.get("url_norm") or "").strip().lower()
    if inu and rnu and inu == rnu:
        return True, "url_norm"

    ih = (inp_ind.get("url_host") or "").strip().lower()
    rh = (row_ind.get("url_host") or "").strip().lower()
    if ih and rh and ih == rh:
        return True, "url_host"

    idom = (inp_ind.get("url_domain") or "").strip().lower()
    rdom = (row_ind.get("url_domain") or "").strip().lower()
    if idom and rdom and idom == rdom:
        return True, "url_domain"

    ip = inp_ind.get("purl") or {}
    rp = row_ind.get("purl") or {}
    if isinstance(ip, dict) and ip.get("name"):
        if isinstance(rp, dict) and rp.get("name") and str(rp["name"]).lower() == str(ip["name"]).lower():
            return True, "purl_name"

    token = (inp_ind.get("name_token") or "").strip().lower()
    if token:
        rx = build_token_regex(token)
        fields = row_ind.get("fields") or {}
        for field in ("name", "commit_link", "purl_link"):
            val = str(fields.get(field) or "")
            if val and rx.search(val):
                return True, f"token_in_{field}"

    return False, ""


def scan_input_against_toxic_db(*, inp: str, kind: str, csv_path: Path) -> Dict[str, Any]:
    s = (inp or "").strip()
    if not s:
        return {"matched": False, "reason": "empty_input", "input": inp, "kind": kind}

    inp_ind = build_indicators_from_input(s, kind)

    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row_ind = build_indicators_from_row(row)
            ok, why = match_input_to_row(inp_ind, row_ind)
            if ok:
                return {
                    "matched": True,
                    "matched_on": why,
                    "input": s,
                    "kind": kind,
                    "problem_type": row.get("problem_type") or "",
                    "row": row,
                }

    return {"matched": False, "input": s, "kind": kind}


def _read_downloads_csv(path: Path) -> List[Dict[str, str]]:
    if not path.is_file():
        return []
    out: List[Dict[str, str]] = []
    with path.open("r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            out.append({k: (v or "").strip() for k, v in row.items()})
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-dir", required=True, help="Job dir (where to write _checks)")
    ap.add_argument("--jobs-cache-root", default=None, help="Dir to store toxic db cache (default: parent jobs dir)")
    ap.add_argument("--downloads-csv", required=True, help="Path to sources_downloads.csv")
    ap.add_argument("--out-csv", default=None, help="Output CSV path (default: <job>/_checks/toxic_repos_report.csv)")
    ap.add_argument("--out-json", default=None, help="Output JSON path (default: <job>/_checks/toxic_repos_status.json)")
    args = ap.parse_args()

    job_dir = Path(args.job_dir).resolve()
    downloads_csv = Path(args.downloads_csv).resolve()

    checks_dir = job_dir / "_checks"
    checks_dir.mkdir(parents=True, exist_ok=True)

    out_csv = Path(args.out_csv).resolve() if args.out_csv else (checks_dir / "toxic_repos_report.csv")
    out_json = Path(args.out_json).resolve() if args.out_json else (checks_dir / "toxic_repos_status.json")

    cache_root = Path(args.jobs_cache_root).resolve() if args.jobs_cache_root else job_dir.parent
    csv_path, meta = ensure_toxic_db_fresh(jobs_dir=cache_root)

    rows = _read_downloads_csv(downloads_csv)

    findings: List[Dict[str, Any]] = []
    checked = 0

    for r in rows:
        primary_url = (r.get("primary_url") or "").strip()
        if not primary_url:
            continue

        kind = "git" if ("github.com" in primary_url.lower() or re.fullmatch(r"[^/\s]+/[^/\s]+", primary_url)) else "wget"
        res = scan_input_against_toxic_db(inp=primary_url, kind=kind, csv_path=csv_path)
        checked += 1

        if res.get("matched"):
            findings.append(
                {
                    "ecosystem": r.get("ecosystem", ""),
                    "name": r.get("name", ""),
                    "version": r.get("version", ""),
                    "primary_url": primary_url,
                    "matched_on": res.get("matched_on", ""),
                    "problem_type": res.get("problem_type", ""),
                    "db_name": (res.get("row") or {}).get("name", ""),
                    "db_commit_link": (res.get("row") or {}).get("commit_link", ""),
                    "db_purl": (res.get("row") or {}).get("PURL", ""),
                    "db_description": (res.get("row") or {}).get("description", ""),
                }
            )

    with out_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "ecosystem",
                "name",
                "version",
                "primary_url",
                "matched_on",
                "problem_type",
                "db_name",
                "db_commit_link",
                "db_purl",
                "db_description",
            ],
        )
        w.writeheader()
        for x in findings:
            w.writerow(x)

    status = {
        "ok": True,
        "checked_urls": checked,
        "matches": len(findings),
        "downloads_csv": str(downloads_csv),
        "out_csv": str(out_csv),
        "toxic_db": {"csv_path": str(csv_path), "meta": meta},
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }
    out_json.write_text(json.dumps(status, ensure_ascii=False, indent=2), encoding="utf-8")

    if findings:
        print(f"[toxic] MATCHES FOUND: {len(findings)} (see {out_csv})")
        return 0

    print(f"[toxic] OK: no matches (checked={checked})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
