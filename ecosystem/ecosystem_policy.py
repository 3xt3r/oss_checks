import os
import fnmatch
import glob
from pathlib import Path

LOCK_FILES_TO_RESEARCH = {
    "requirements.txt",
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "conda-lock.yml",
    "conda-*.lock.yml",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lockb",
    "bun.lock",
    "packages.lock.json",
    "go.sum",
    "gradle.lockfile",
    "*.sbt.lock",
    "composer.lock",
    "Gemfile.lock",
    "Cargo.lock",
    "pubspec.lock",
    "Package.resolved",
    "Podfile.lock",
    "Manifest.toml",
}

BUILD_ARTIFACT_PATTERNS = [
    "*.deps.json",
    "installed.json",
]

def is_build_artifact(filename: str) -> bool:
    return any(fnmatch.fnmatch(filename, p) for p in BUILD_ARTIFACT_PATTERNS)

DEFAULT_SKIP_DIRS = {
    ".git", ".hg", ".svn",
    ".idea", ".vscode", "__pycache__",
    "node_modules", "target", "bin", "obj",
    ".gradle", ".mvn",
}

DEFAULT_PRUNE_TOP_LEVEL_DIRS = {"sources"}

def walk_files(root: str, include_sources: bool = False):
    root = os.path.abspath(root)

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in DEFAULT_SKIP_DIRS]

        if not include_sources:
            if "sources" in dirnames:
                dirnames.remove("sources")

        yield dirpath, filenames

def any_lock_present(dirpath: str, lock_patterns: list) -> bool:
    for lp in lock_patterns:
        if glob.glob(os.path.join(dirpath, lp)):
            return True
    return False

def path_has_any(root: str, start_dir: str, patterns: list) -> bool:
    root_path = Path(root).resolve()
    cur = Path(start_dir).resolve()

    while True:
        for name in patterns:
            if "*" in name or "?" in name or "[" in name:
                if glob.glob(str(cur / name)):
                    return True
            else:
                if (cur / name).exists():
                    return True

        if cur == root_path or cur.parent == cur:
            break
        cur = cur.parent

    return False

SOURCE_TO_LOCK_STATIC_RAW = {
    "package.json": [
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lockb",
        "bun.lock",
    ],
    "*.csproj": ["packages.lock.json"],
    "*.fsproj": ["packages.lock.json"],
    "*.vbproj": ["packages.lock.json"],
    "packages.config": ["packages.lock.json"],
    "Directory.Packages.props": ["packages.lock.json"],
    "Pipfile": ["Pipfile.lock"],
    "requirements.in": ["requirements.txt"],
    "environment.yml": ["conda-lock.yml", "conda-*.lock.yml"],
    "go.mod": ["go.sum"],
    "build.gradle": ["gradle.lockfile"],
    "build.gradle.kts": ["gradle.lockfile"],
    "build.sbt": ["*.sbt.lock"],
    "Gemfile": ["Gemfile.lock"],
    "*.gemspec": ["Gemfile.lock"],
    "Cargo.toml": ["Cargo.lock"],
    "pubspec.yaml": ["pubspec.lock"],
    "composer.json": ["composer.lock"],
    "Package.swift": ["Package.resolved"],
    "Podfile": ["Podfile.lock"],
    "Project.toml": ["Manifest.toml"],
}

def filter_source_to_lock(raw: dict, allowed_locks: set) -> dict:
    filtered = {}
    for manifest_pat, locks in raw.items():
        keep = [l for l in locks if l in allowed_locks]
        if keep:
            filtered[manifest_pat] = keep
    return filtered

SOURCE_TO_LOCK_STATIC = filter_source_to_lock(SOURCE_TO_LOCK_STATIC_RAW, LOCK_FILES_TO_RESEARCH)

def detect_pyproject_tool(pyproject_path: str) -> str | None:
    try:
        with open(pyproject_path, "r", encoding="utf-8") as f:
            data = f.read()
            if "[tool.poetry]" in data:
                return "poetry"
            if "[tool.uv]" in data:
                return "uv"
    except OSError:
        return None
    return None

def expected_locks_for_pyproject(pyproject_path: str) -> list[str]:
    tool = detect_pyproject_tool(pyproject_path)
    if tool == "poetry":
        return ["poetry.lock"]
    if tool == "uv":
        return ["uv.lock"]
    return []

def warn_about_unresearched_locks(raw: dict, allowed_locks: set) -> list[str]:
    unknown = set()
    for locks in raw.values():
        for l in locks:
            if l not in allowed_locks:
                unknown.add(l)
    return sorted(unknown)
