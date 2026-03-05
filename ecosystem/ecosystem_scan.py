import os
import fnmatch
import argparse
import json
import glob
from pathlib import Path

import ecosystem_policy as policy


NODE_LOCK_FILES = [
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lockb",
    "bun.lock",
]
NODE_MANIFESTS = ["package.json"]

NODE_TOOL_HINTS = {
    "webpack.config.*": "Webpack",
    "vite.config.*": "Vite",
    "rollup.config.*": "Rollup",
    "esbuild.config.*": "esbuild",
    "parcel.config.*": "Parcel",
    "babel.config.*": "Babel",
    ".babelrc": "Babel",
    ".babelrc.*": "Babel",
    "tsconfig.json": "TypeScript",
    "tsconfig.*.json": "TypeScript",
    "jest.config.*": "Jest",
    ".eslintrc": "ESLint",
    ".eslintrc.*": "ESLint",
    "eslint.config.*": "ESLint (flat config)",
    ".prettierrc": "Prettier",
    ".prettierrc.*": "Prettier",
    "prettier.config.*": "Prettier",
    "lerna.json": "Lerna",
    "nx.json": "Nx",
    "turbo.json": "Turborepo",
    "rush.json": "Rush",
    "gulpfile.js": "Gulp",
    "gulpfile.mjs": "Gulp",
    "gulpfile.cjs": "Gulp",
    "gruntfile.js": "Grunt",
    "gruntfile.coffee": "Grunt",
}

PY_DEP_MANIFEST_OR_LOCK = [
    "pyproject.toml",
    "Pipfile",
    "requirements.in",
    "requirements.txt",
    "environment.yml",
    "setup.py",
    "setup.cfg",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "conda-lock.yml",
]

PY_TOOL_HINTS = {
    "tox.ini": "tox",
    "pytest.ini": "pytest",
    "noxfile.py": "nox",
    "setup.py": "setuptools",
    "setup.cfg": "setuptools",
    "manage.py": "Django",
    ".flake8": "flake8",
    "mypy.ini": "mypy",
    ".mypy.ini": "mypy",
    "pyrightconfig.json": "pyright",
}

RUBY_DEP_MANIFEST_OR_LOCK = ["Gemfile", "Gemfile.lock", "*.gemspec"]
RUBY_TOOL_HINTS = {
    "Rakefile": "Rake",
    "Rakefile.rb": "Rake",
    "*.rake": "Rake",
    "config.ru": "Rack app",
    ".rubocop.yml": "RuboCop",
    ".rubocop.yaml": "RuboCop",
}

PHP_DEP_MANIFEST_OR_LOCK = ["composer.json", "composer.lock"]
PHP_TOOL_HINTS = {
    "artisan": "Laravel",
    "phpunit.xml": "PHPUnit",
    "phpunit.xml.dist": "PHPUnit",
    "phpcs.xml": "PHP_CodeSniffer",
    "phpcs.xml.dist": "PHP_CodeSniffer",
    "phpspec.yml": "PHPSpec",
    "phpspec.yml.dist": "PHPSpec",
    "codeception.yml": "Codeception",
}

RUST_DEP_MANIFEST_OR_LOCK = ["Cargo.toml", "Cargo.lock"]
DART_DEP_MANIFEST_OR_LOCK = ["pubspec.yaml", "pubspec.lock"]
SWIFT_DEP_MANIFEST_OR_LOCK = ["Package.swift", "Package.resolved", "Podfile", "Podfile.lock"]
JULIA_DEP_MANIFEST_OR_LOCK = ["Project.toml", "Manifest.toml"]


def guess_ecosystem(name):
    base = os.path.basename(name)
    if base == "package.json": return "Node.js"
    if base.endswith((".csproj", ".fsproj", ".vbproj")): return ".NET"
    if base in ("pyproject.toml", "Pipfile", "requirements.in", "environment.yml"): return "Python"
    if base == "go.mod": return "Go"
    if base.startswith("build.gradle"): return "Gradle"
    if base == "build.sbt": return "SBT"
    if base == "Gemfile" or base.endswith(".gemspec"): return "Ruby"
    if base == "Cargo.toml": return "Rust"
    if base == "pubspec.yaml": return "Dart"
    if base == "composer.json": return "PHP"
    if base == "Package.swift": return "SwiftPM"
    if base == "Podfile": return "CocoaPods"
    if base == "Project.toml": return "Julia"
    if base == "pom.xml": return "Maven"
    return "unknown"


def collect_manifests(root: str, include_sources: bool):
    manifests = []

    for dirpath, filenames in policy.walk_files(root, include_sources=include_sources):
        for filename in filenames:
            if policy.is_build_artifact(filename):
                continue

            for pattern, locks in policy.SOURCE_TO_LOCK_STATIC.items():
                if fnmatch.fnmatch(filename, pattern):
                    fp = os.path.join(dirpath, filename)
                    rel = os.path.relpath(fp, root)
                    lock_found = policy.any_lock_present(dirpath, locks)

                    manifests.append({
                        "ecosystem": guess_ecosystem(rel),
                        "manifest": rel,
                        "expected_locks": locks,
                        "lock_found": lock_found,
                    })

            if filename == "pyproject.toml":
                pyproject_path = os.path.join(dirpath, filename)
                locks = policy.expected_locks_for_pyproject(pyproject_path)
                if not locks:
                    continue

                rel = os.path.relpath(pyproject_path, root)
                lock_found = policy.any_lock_present(dirpath, locks)

                manifests.append({
                    "ecosystem": "Python",
                    "manifest": rel,
                    "expected_locks": locks,
                    "lock_found": lock_found,
                })

    return manifests


def find_node_tool_hints(root, include_sources: bool):
    hints = []
    for dirpath, filenames in policy.walk_files(root, include_sources=include_sources):
        for filename in filenames:
            for pattern, tool in NODE_TOOL_HINTS.items():
                if fnmatch.fnmatch(filename, pattern):
                    rel = os.path.relpath(os.path.join(dirpath, filename), root)
                    hints.append({
                        "tool": tool,
                        "file": rel,
                        "dir": os.path.relpath(dirpath, root),
                        "has_pkg_json": any(os.path.exists(os.path.join(dirpath, m)) for m in NODE_MANIFESTS),
                        "has_lock": any(os.path.exists(os.path.join(dirpath, l)) for l in NODE_LOCK_FILES),
                    })
    return hints


def find_tools_generic(root, hint_map, dep_files, include_sources: bool):
    hints = []
    for dirpath, filenames in policy.walk_files(root, include_sources=include_sources):
        for filename in filenames:
            for pattern, tool in hint_map.items():
                if fnmatch.fnmatch(filename, pattern):
                    rel = os.path.relpath(os.path.join(dirpath, filename), root)
                    has_deps = policy.path_has_any(root, dirpath, dep_files)
                    hints.append({
                        "tool": tool,
                        "file": rel,
                        "dir": os.path.relpath(dirpath, root),
                        "has_deps": has_deps,
                    })
    return hints


def detect_simple(root, extensions, dep_patterns, ecosystem, include_sources: bool):
    results = []
    root_path = Path(root).resolve()

    if isinstance(extensions, str):
        extensions = (extensions,)

    for dirpath, filenames in policy.walk_files(root, include_sources=include_sources):
        if not any(f.endswith(extensions) for f in filenames):
            continue
        has_dep = policy.path_has_any(str(root_path), dirpath, dep_patterns)
        results.append({"dir": os.path.relpath(dirpath, root), "upwards": has_dep, "ecosystem": ecosystem})
    return results


def detect_go(root, include_sources: bool): return detect_simple(root, ".go", ["go.mod", "go.sum"], "Go", include_sources)
def detect_rust(root, include_sources: bool): return detect_simple(root, ".rs", RUST_DEP_MANIFEST_OR_LOCK, "Rust", include_sources)
def detect_dart(root, include_sources: bool): return detect_simple(root, ".dart", DART_DEP_MANIFEST_OR_LOCK, "Dart", include_sources)
def detect_swift(root, include_sources: bool): return detect_simple(root, (".swift", ".m", ".mm"), SWIFT_DEP_MANIFEST_OR_LOCK, "Swift", include_sources)
def detect_julia(root, include_sources: bool): return detect_simple(root, ".jl", JULIA_DEP_MANIFEST_OR_LOCK, "Julia", include_sources)


def detect_maven(root, include_sources: bool):
    poms = []
    for dirpath, filenames in policy.walk_files(root, include_sources=include_sources):
        if "pom.xml" in filenames:
            poms.append({"pom": os.path.relpath(os.path.join(dirpath, "pom.xml"), root)})
    return poms


def detect_build_artifacts(root, include_sources: bool):
    out = []
    for dirpath, filenames in policy.walk_files(root, include_sources=include_sources):
        for f in filenames:
            if policy.is_build_artifact(f):
                out.append({"file": os.path.relpath(os.path.join(dirpath, f), root)})
    return out


def append(md, text=""):
    md.append(text)


def main():
    p = argparse.ArgumentParser(description="Scan dependency manifests/tools and write report.md")
    p.add_argument("path")
    p.add_argument("--json", action="store_true")
    p.add_argument("--include-sources", action="store_true", help="Also scan vendored 'sources/' directory")
    args = p.parse_args()

    root = os.path.abspath(args.path)

    manifests = collect_manifests(root, include_sources=args.include_sources)
    node_tools = find_node_tool_hints(root, include_sources=args.include_sources)
    py_tools = find_tools_generic(root, PY_TOOL_HINTS, PY_DEP_MANIFEST_OR_LOCK, include_sources=args.include_sources)
    ruby_tools = find_tools_generic(root, RUBY_TOOL_HINTS, RUBY_DEP_MANIFEST_OR_LOCK, include_sources=args.include_sources)
    php_tools = find_tools_generic(root, PHP_TOOL_HINTS, PHP_DEP_MANIFEST_OR_LOCK, include_sources=args.include_sources)

    go_code = detect_go(root, include_sources=args.include_sources)
    rust_code = detect_rust(root, include_sources=args.include_sources)
    dart_code = detect_dart(root, include_sources=args.include_sources)
    swift_code = detect_swift(root, include_sources=args.include_sources)
    julia_code = detect_julia(root, include_sources=args.include_sources)
    maven = detect_maven(root, include_sources=args.include_sources)
    artifacts = detect_build_artifacts(root, include_sources=args.include_sources)

    if args.json:
        print(json.dumps({
            "manifests": manifests,
            "node_tools": node_tools,
            "python_tools": py_tools,
            "ruby_tools": ruby_tools,
            "php_tools": php_tools,
            "go": go_code,
            "rust": rust_code,
            "dart": dart_code,
            "swift": swift_code,
            "julia": julia_code,
            "maven": maven,
            "build_artifacts": artifacts,
            "source_to_lock_static": policy.SOURCE_TO_LOCK_STATIC,
        }, indent=2))
        return

    md = []
    append(md, "# Dependency and Ecosystem Scan Report\n")
    append(md, "## Package Manager Manifests\n")
    append(md, "| Ecosystem | Manifest | Lock Found | Expected Lock Files |")
    append(md, "|----------|----------|------------|----------------------|")
    for m in manifests:
        append(md, f"| {m['ecosystem']} | `{m['manifest']}` | {'YES' if m['lock_found'] else 'NO'} | `{', '.join(m['expected_locks'])}` |")
    append(md, "")

    append(md, "## JS / TS Tools\n")
    append(md, "| File | Tool | Directory | package.json | Lock File |")
    append(md, "|------|------|-----------|---------------|-----------|")
    for t in node_tools:
        append(md, f"| `{t['file']}` | {t['tool']} | `{t['dir']}` | {'YES' if t['has_pkg_json'] else 'NO'} | {'YES' if t['has_lock'] else 'NO'} |")
    append(md, "")

    def write_simple_tools(title, tools):
        append(md, f"## {title}\n")
        append(md, "| File | Tool | Directory | Manifest/Lock Upwards |")
        append(md, "|------|------|-----------|------------------------|")
        for t in tools:
            append(md, f"| `{t['file']}` | {t['tool']} | `{t['dir']}` | {'YES' if t['has_deps'] else 'NO'} |")
        append(md, "")

    write_simple_tools("Python Tools", py_tools)
    write_simple_tools("Ruby Tools", ruby_tools)
    write_simple_tools("PHP Tools", php_tools)

    def write_lang(title, arr):
        append(md, f"## {title}\n")
        append(md, "| Directory | Manifest/Lock Upwards |")
        append(md, "|-----------|------------------------|")
        for h in arr:
            append(md, f"| `{h['dir']}` | {'YES' if h['upwards'] else 'NO'} |")
        append(md, "")

    write_lang("Go Code", go_code)
    write_lang("Rust Code", rust_code)
    write_lang("Dart / Flutter Code", dart_code)
    write_lang("Swift / ObjC Code", swift_code)
    write_lang("Julia Code", julia_code)

    append(md, "## Java / Maven\n")
    append(md, "| pom.xml | Note |")
    append(md, "|---------|------|")
    for p2 in maven:
        append(md, f"| `{p2['pom']}` | Maven has no standard lock file (policy/tooling dependent) |")
    append(md, "")

    append(md, "## Build / Install Artifacts (Not Lock Files)\n")
    append(md, "| File |")
    append(md, "|------|")
    for a in artifacts:
        append(md, f"| `{a['file']}` |")
    append(md, "")

    report_path = os.path.join(root, "report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    print("Markdown report saved to:", report_path)


if __name__ == "__main__":
    main()
