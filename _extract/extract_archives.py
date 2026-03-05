import os
import shutil
import tarfile
import zipfile
import gzip
import bz2
import lzma
import py7zr
import rarfile
import subprocess
from pathlib import Path

SUPPORTED_EXT = [
    ".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz",
    ".gz", ".bz2", ".xz", ".7z", ".rar", ".deb", ".rpm", ".iso"
]

def extract_tar(file_path, dest):
    with tarfile.open(file_path, 'r:*') as tar:
        tar.extractall(dest)

def extract_zip(file_path, dest):
    with zipfile.ZipFile(file_path, 'r') as zf:
        zf.extractall(dest)

def extract_gz(file_path, dest):
    output_file = os.path.join(dest, Path(file_path).stem)
    with gzip.open(file_path, 'rb') as f_in, open(output_file, 'wb') as f_out:
        shutil.copyfileobj(f_in, f_out)

def extract_bz2(file_path, dest):
    output_file = os.path.join(dest, Path(file_path).stem)
    with bz2.open(file_path, 'rb') as f_in, open(output_file, 'wb') as f_out:
        shutil.copyfileobj(f_in, f_out)

def extract_xz(file_path, dest):
    output_file = os.path.join(dest, Path(file_path).stem)
    with lzma.open(file_path, 'rb') as f_in, open(output_file, 'wb') as f_out:
        shutil.copyfileobj(f_in, f_out)

def extract_7z(file_path, dest):
    with py7zr.SevenZipFile(file_path, mode='r') as z:
        z.extractall(path=dest)

def extract_rar(file_path, dest):
    with rarfile.RarFile(file_path) as rf:
        rf.extractall(path=dest)

def extract_deb(file_path, dest):
    try:
        os.makedirs(dest, exist_ok=True)
        subprocess.run(["dpkg-deb", "-x", file_path, dest], check=True)
    except Exception as e:
        print(f"[!] dpkg-deb failed: {e}")

def extract_rpm(file_path, dest):
    try:
        os.makedirs(dest, exist_ok=True)
        command = f"rpm2cpio '{file_path}' | (cd '{dest}' && cpio -idmv)"
        subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"[!] rpm2cpio failed: {e}")

def _extract_iso_with_7z(file_path, dest):
    try:
        os.makedirs(dest, exist_ok=True)
        subprocess.run(
            ["7z", "x", "-y", f"-o{dest}", file_path],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return True
    except Exception as e:
        print(f"[!] 7z failed to extract ISO: {e}")
        return False

def extract_iso(file_path, dest):
    try:
        import pycdlib
    except ImportError:
        print("[i] pycdlib not installed, trying 7z…")
        return _extract_iso_with_7z(file_path, dest)

    cd = pycdlib.PyCdlib()
    try:
        cd.open(file_path)
        os.makedirs(dest, exist_ok=True)

        extracted = False
        modes = [
            ("udf_path", "/"),
            ("rr_path", "/"),
            ("joliet_path", "/"),
            ("iso_path", "/"),
        ]

        for key, root_path in modes:
            try:
                for root, dirs, files in cd.walk(**{key: root_path}):
                    local_root = os.path.join(dest, root.lstrip("/"))
                    os.makedirs(local_root, exist_ok=True)
                    for d in dirs:
                        os.makedirs(os.path.join(local_root, d), exist_ok=True)
                    for fn in files:
                        iso_entry = os.path.join(root, fn)
                        out_path = os.path.join(local_root, fn)
                        with open(out_path, "wb") as outfp:
                            cd.get_file_from_iso(outfp, **{key: iso_entry})
                extracted = True
                break
            except Exception:
                continue

        cd.close()
        if extracted:
            return True

        print("[i] Could not extract ISO via pycdlib, trying 7z…")
        return _extract_iso_with_7z(file_path, dest)

    except Exception as e:
        try:
            cd.close()
        except Exception:
            pass
        print(f"[!] pycdlib error: {e}. Trying 7z…")
        return _extract_iso_with_7z(file_path, dest)

def extract_archive(file_path, dest):
    ext = "".join(Path(file_path).suffixes).lower()
    try:
        if ext.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")):
            extract_tar(file_path, dest)
        elif ext.endswith(".zip"):
            extract_zip(file_path, dest)
        elif ext.endswith(".gz"):
            extract_gz(file_path, dest)
        elif ext.endswith(".bz2"):
            extract_bz2(file_path, dest)
        elif ext.endswith(".xz"):
            extract_xz(file_path, dest)
        elif ext.endswith(".7z"):
            extract_7z(file_path, dest)
        elif ext.endswith(".rar"):
            extract_rar(file_path, dest)
        elif ext.endswith(".deb"):
            extract_deb(file_path, dest)
        elif ext.endswith(".rpm"):
            extract_rpm(file_path, dest)
        elif ext.endswith(".iso"):
            if not extract_iso(file_path, dest):
                print(f"[!] Unsupported or failed ISO: {file_path}")
                return False
        else:
            print(f"[!] Unsupported: {file_path}")
            return False

        print(f"[+] Extracted: {file_path}")
        os.remove(file_path)
        return True

    except Exception as e:
        print(f"[!] Failed to extract {file_path}: {e}")
        return False

def recursive_extract(path):
    for root, dirs, files in os.walk(path):
        for file in files:
            full_path = os.path.join(root, file)
            if any(full_path.lower().endswith(e) for e in SUPPORTED_EXT):
                extract_to = os.path.join(root, f"extracted_{Path(file).stem}")
                os.makedirs(extract_to, exist_ok=True)
                if extract_archive(full_path, extract_to):
                    recursive_extract(extract_to)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Recursively extract and remove archives")
    parser.add_argument("target", help="Path to directory or file")
    args = parser.parse_args()

    input_path = Path(args.target).resolve()
    if input_path.is_file():
        extract_to = input_path.parent / f"extracted_{input_path.stem}"
        os.makedirs(extract_to, exist_ok=True)
        if extract_archive(str(input_path), str(extract_to)):
            recursive_extract(str(extract_to))
    else:
        recursive_extract(str(input_path))
