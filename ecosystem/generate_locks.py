#!/usr/bin/env python3
import os
import fnmatch
import argparse
import json
import glob
import subprocess

import ecosystem_policy as policy


def find_manifests(root: str, include_sources: bool):
    root = os.path.abspath(root)
    manifests = []

    for dirpath, filenames in policy.walk_files(root, include_sources=include_sources):
        for filename in filenames:
            if policy.is_build_artifact(filename):
                continue

            # 1) static mapping
            for pattern, lock_patterns in policy.SOURCE_TO_LOCK_STATIC.items():
                if fnmatch.fnmatch(filename, pattern):
                    full = os.path.join(dirpath, filename)
                    rel = os.path.relpath(full, root)
                    lock_found = any(glob.glob(os.path.join(dirpath, lp)) for lp in lock_patterns)

                    manifests.append({
                        "manifest": rel,
                        "dir": os.path.relpath(dirpath, root),
                        "abs_dir": dirpath,
                        "expected_locks": lock_patterns,
                        "lock_found": lock_found,
                        "pattern": pattern,
                    })

            # 2) pyproject conditional
            if filename == "pyproject.toml":
                pyproject_path = os.path.join(dirpath, filename)
                locks = policy.expected_locks_for_pyproject(pyproject_path)
                if not locks:
                    continue

                rel = os.path.relpath(pyproject_path, root)
                lock_found = any(glob.glob(os.path.join(dirpath, lp)) for lp in locks)

                manifests.append({
                    "manifest": rel,
                    "dir": os.path.relpath(dirpath, root),
                    "abs_dir": dirpath,
                    "expected_locks": locks,
                    "lock_found": lock_found,
                    "pattern": "pyproject.toml",
                })

    return manifests


def command_for_manifest(root: str, entry: dict):
    pattern = entry["pattern"]
    abs_dir = entry["abs_dir"]
    manifest_rel = entry["manifest"]
    manifest_abs = os.path.join(root, manifest_rel)

    if pattern == "package.json":
        return f'cd "{abs_dir}" && npm install --package-lock-only', "Node lock is ONE-OF; command shown for npm (package-lock.json)."

    if pattern == "composer.json":
        cmd = (
            f'cd "{abs_dir}" && '
            'composer update --no-install '
            '--ignore-platform-req=ext-xml '
            '--ignore-platform-req=ext-dom'
        )
        return cmd, "Generates/updates composer.lock."

    if pattern.endswith((".csproj", ".fsproj", ".vbproj")):
        return f'cd "{root}" && dotnet restore "{manifest_rel}" --use-lock-file', "Generates packages.lock.json for this .NET project."

    if pattern in ("packages.config", "Directory.Packages.props"):
        return f'cd "{root}" && dotnet restore --use-lock-file', "Generates packages.lock.json (solution/project dependent)."

    if pattern == "Gemfile" or pattern.endswith(".gemspec"):
        return f'cd "{abs_dir}" && bundle lock', "Generates Gemfile.lock."

    if pattern == "Pipfile":
        return f'cd "{abs_dir}" && pipenv lock', "Generates Pipfile.lock."

    if pattern == "requirements.in":
        return f'cd "{abs_dir}" && pip-compile requirements.in', "Generates requirements.txt via pip-tools."

    if pattern == "environment.yml":
        return f'cd "{abs_dir}" && conda-lock -f environment.yml', "Generates conda-lock.yml via conda-lock."

    if pattern == "pyproject.toml":
        tool = policy.detect_pyproject_tool(manifest_abs)
        if tool == "poetry":
            return f'cd "{abs_dir}" && poetry lock', "Detected Poetry; runs 'poetry lock'."
        if tool == "uv":
            return f'cd "{abs_dir}" && uv lock', "Detected uv; runs 'uv lock'."
        return None, "pyproject.toml found but no Poetry/uv markers; no safe default command."

    if pattern == "go.mod":
        return f'cd "{abs_dir}" && go mod tidy', "Generates/updates go.sum."

    if pattern == "Cargo.toml":
        return f'cd "{abs_dir}" && cargo generate-lockfile', "Generates Cargo.lock."

    if pattern == "pubspec.yaml":
        return f'cd "{abs_dir}" && dart pub get', "Generates/updates pubspec.lock."

    if pattern == "Package.swift":
        return f'cd "{abs_dir}" && swift package resolve', "Generates/updates Package.resolved."

    if pattern == "Podfile":
        return f'cd "{abs_dir}" && pod install', "Generates/updates Podfile.lock."

    if pattern == "Project.toml":
        return f'cd "{abs_dir}" && julia -e "using Pkg; Pkg.instantiate()"', "Generates/updates Manifest.toml."

    if pattern in ("build.gradle", "build.gradle.kts"):
        return None, "Gradle locking is configuration-dependent; no universal command."
    if pattern == "build.sbt":
        return None, "SBT lock generation depends on plugins; no universal command."

    return None, "No automatic lock generation rule."


def run_command(cmd: str):
    try:
        r = subprocess.run(cmd, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:
        return -1, "", str(e)


def main():
    p = argparse.ArgumentParser(description="Generate lock files via package managers for detected manifests.")
    p.add_argument("path", help="Path to project root")
    p.add_argument("--apply", action="store_true", help="Execute commands instead of dry-run")
    p.add_argument("--md", action="store_true", help="Save plan to lock-plan.md")
    p.add_argument("--json", action="store_true", help="Print JSON with planned actions")
    p.add_argument("--include-sources", action="store_true", help="Also scan vendored 'sources/' directory")
    args = p.parse_args()

    root = os.path.abspath(args.path)

    manifests = find_manifests(root, include_sources=args.include_sources)
    missing = [m for m in manifests if not m["lock_found"]]

    print(f"Root: {root}")
    print(f"Found {len(missing)} manifests without lock files.\n")

    suggestions = []
    for m in missing:
        cmd, notes = command_for_manifest(root, m)
        suggestions.append({
            "manifest": m["manifest"],
            "dir": m["dir"],
            "abs_dir": m["abs_dir"],
            "expected_locks": m["expected_locks"],
            "command": cmd,
            "notes": notes,
        })

    if args.json:
        print(json.dumps(suggestions, indent=2))
        print()

    print("Planned actions:")
    print("----------------")
    plan_lines = []
    for s in suggestions:
        print(f"- Manifest : {s['manifest']}")
        print(f"  Dir      : {s['dir']}")
        print(f"  Locks    : {', '.join(s['expected_locks'])}")
        print(f"  Command  : {s['command'] or '(none)'}")
        print(f"  Notes    : {s['notes']}\n")
        plan_lines.append(f"* `{s['manifest']}` → `{s['command'] or '(no command)'}` — {s['notes']}")

    if args.md:
        md_path = os.path.join(root, "lock-plan.md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write("# Lock File Generation Plan\n\n")
            f.write(f"Root: `{root}`\n\n")
            f.write("\n".join(plan_lines))
            f.write("\n")
        print(f"lock-plan.md saved to {md_path}\n")

    if not args.apply:
        print("Dry-run only. Use --apply to actually run these commands.")
        return

    print("Applying lock generation commands...")
    print("------------------------------------")
    for s in suggestions:
        if not s["command"]:
            print(f"- Skipping {s['manifest']}: no automatic command.")
            continue

        print(f"- {s['manifest']}:")
        print(f"  -> EXEC: {s['command']}")
        code, out, err = run_command(s["command"])

        if code == 0:
            if out.strip():
                print(out)
            print("  OK\n")
        else:
            if out.strip():
                print(out)
            if err.strip():
                print(err)
            print(f"  !! ERROR: command failed with code {code}")
            print("  FAILED\n")

    print("Done.")


if __name__ == "__main__":
    main()

