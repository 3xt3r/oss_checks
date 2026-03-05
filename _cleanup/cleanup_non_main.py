import os
import shutil
from pathlib import Path

GARBAGE_DIR_NAMES = {
    "test", "tests", "__tests__", "testing",
    "spec", "specs",
    "unit", "units",
    "integration", "integration-test", "integrationtests",
    "it", "its",
    "e2e",
    "example", "examples",
    "sample", "samples",
    "demo", "demos",
    "doc", "docs", "documentation",
    "apidocs", "api-docs",
    "site", "website",
}

GARBAGE_FILE_PATTERNS = [
    "test_*",
    "*_test.*",
    "*.test.*",
    "*.spec.*",
    "*.integration.*",
    "*.e2e.*",
    "example_*",
    "*_example.*",
    "*.example.*",
    "sample_*",
    "*_sample.*",
    "*.sample.*",
    "*.Test.*",
    "*.Test.Sdk-*",
]


def delete_non_main_code(root_path: str) -> None:
    root = Path(root_path)

    for dirpath, dirnames, filenames in os.walk(root_path, topdown=True):
        to_delete = []
        for d in dirnames:
            if d.lower() in GARBAGE_DIR_NAMES:
                to_delete.append(os.path.join(dirpath, d))

        for d in to_delete:
            print(f"[cleanup] removing directory: {d}")
            shutil.rmtree(d, ignore_errors=True)
            dn = os.path.basename(d)
            if dn in dirnames:
                dirnames.remove(dn)

    for dirpath, dirnames, filenames in os.walk(root_path):
        for file in filenames:
            fname = file.lower()
            for pattern in GARBAGE_FILE_PATTERNS:
                if Path(fname).match(pattern):
                    fpath = os.path.join(dirpath, file)
                    print(f"[cleanup] removing file: {fpath}")
                    try:
                        os.remove(fpath)
                    except Exception:
                        pass
                    break
