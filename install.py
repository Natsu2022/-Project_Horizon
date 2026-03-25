#!/usr/bin/env python3
"""
install.py — VA Scanner One-time Setup
=======================================
Cross-platform installer for Windows, macOS, and Linux.
Uses Python stdlib only — no external packages required.

Steps:
  1. Verify Python >= 3.9  (auto-download installer if too old)
  2. Verify Go >= 1.21     (auto-download installer if missing or outdated)
  3. Create Python virtual environment (venv/)
  4. Install packages from requirements.txt

Run via:
  Windows        : install.bat  (or python install.py)
  macOS / Linux  : sh install.sh  (or python3 install.py)
"""

import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import urllib.request
import venv

# ── Minimum versions ──────────────────────────────────────────────────────────
MIN_PYTHON = (3, 9)
MIN_GO     = (1, 21)

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
VENV_DIR    = os.path.join(SCRIPT_DIR, "venv")
REQ_FILE    = os.path.join(SCRIPT_DIR, "requirements.txt")
IS_WINDOWS  = platform.system() == "Windows"
BIN         = "Scripts" if IS_WINDOWS else "bin"
EXE         = ".exe" if IS_WINDOWS else ""
VENV_PYTHON = os.path.join(VENV_DIR, BIN, f"python{EXE}")

# ── Python installer URLs (update when a newer Python ships) ──────────────────
_PY_VER  = "3.13.1"
PYTHON_URLS = {
    "Windows": f"https://www.python.org/ftp/python/{_PY_VER}/python-{_PY_VER}-amd64.exe",
    "Darwin":  f"https://www.python.org/ftp/python/{_PY_VER}/python-{_PY_VER}-macos11.pkg",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _prompt(msg: str) -> bool:
    """Ask a Y/n question. Enter or 'y' returns True; 'n' returns False."""
    try:
        ans = input(msg).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return ans in ("", "y", "yes")


def _download(url: str, dest: str) -> None:
    """Download url → dest, printing a simple progress bar."""
    def _hook(count, block_size, total_size):
        if total_size > 0:
            pct = min(100, int(count * block_size * 100 / total_size))
            print(f"\r  Downloading... {pct}%  ", end="", flush=True)
        else:
            print(f"\r  Downloading...       ", end="", flush=True)
    urllib.request.urlretrieve(url, dest, _hook)
    print()  # newline after progress bar


def _launch_file(path: str) -> None:
    """Open a file using the OS default handler (e.g. launch an installer GUI)."""
    system = platform.system()
    if system == "Windows":
        os.startfile(path)
    elif system == "Darwin":
        subprocess.run(["open", path])
    else:
        subprocess.run(["xdg-open", path])


def _parse_go_version(text: str):
    """Parse 'go version go1.X.Y ...' → (X, Y) int tuple, or None."""
    m = re.search(r"go(\d+)\.(\d+)", text)
    return (int(m.group(1)), int(m.group(2))) if m else None


# ── Step 1: Check Python ──────────────────────────────────────────────────────

def check_python():
    ver = sys.version_info
    ver_str = f"{ver.major}.{ver.minor}.{ver.micro}"
    req_str = f"{MIN_PYTHON[0]}.{MIN_PYTHON[1]}"

    if (ver.major, ver.minor) >= MIN_PYTHON:
        print(f"[Check] Python  ... found {ver_str}  \u2713")
        return

    print(f"[Check] Python  ... found {ver_str}  \u2717  (requires {req_str}+)")
    _offer_python_install()


def _offer_python_install():
    system  = platform.system()
    req_str = f"{MIN_PYTHON[0]}.{MIN_PYTHON[1]}"

    if system == "Linux":
        print(f"\n  Python {req_str}+ is required.")
        print("  Install with your package manager, e.g.:")
        print("    sudo apt install python3")
        print("    sudo dnf install python3")
        sys.exit(1)

    url = PYTHON_URLS.get(system)
    if not url:
        print(f"\n  Download Python {req_str}+ from https://www.python.org/downloads/")
        sys.exit(1)

    print(f"\n  Python {req_str}+ is required.")
    if not _prompt(f"  Download Python {_PY_VER} installer? [Y/n]: "):
        print(f"  Download manually: https://www.python.org/downloads/")
        sys.exit(1)

    tmp  = tempfile.mkdtemp()
    dest = os.path.join(tmp, os.path.basename(url))
    _download(url, dest)

    if not _prompt(f"  Downloaded: {dest}\n  Launch installer now? [Y/n]: "):
        print(f"  Run manually: {dest}")
        sys.exit(1)

    _launch_file(dest)
    print(f"\n  Python {_PY_VER} installer launched.")
    print("  After installation completes, re-run install.py to continue setup.")
    sys.exit(0)


# ── Step 2: Check Go ──────────────────────────────────────────────────────────

def check_go():
    found = None
    try:
        result = subprocess.run(
            ["go", "version"], capture_output=True, text=True, timeout=10
        )
        found = _parse_go_version(result.stdout)
    except FileNotFoundError:
        pass

    req_str = f"{MIN_GO[0]}.{MIN_GO[1]}"

    if found is None:
        print(f"[Check] Go      ... not found     \u2717")
        _offer_go_install()
        return

    ver_str = ".".join(str(x) for x in found)
    if found >= MIN_GO:
        print(f"[Check] Go      ... found {ver_str:<8}  \u2713")
        return

    print(f"[Check] Go      ... found {ver_str:<8}  \u2717  (requires {req_str}+)")
    _offer_go_install()


def _offer_go_install():
    system  = platform.system()
    machine = platform.machine().lower()
    arch    = "arm64" if machine in ("arm64", "aarch64") else "amd64"

    # Fetch latest stable release info from go.dev
    print("\n  Fetching latest Go release info...")
    try:
        with urllib.request.urlopen("https://go.dev/dl/?mode=json", timeout=10) as resp:
            releases = json.loads(resp.read())

        latest   = releases[0]
        go_ver   = latest["version"]                 # e.g. "go1.24.2"
        ver_str  = go_ver.lstrip("go")               # e.g. "1.24.2"

        os_map   = {"Windows": "windows", "Darwin": "darwin", "Linux": "linux"}
        kind_map = {"Windows": "installer", "Darwin": "installer", "Linux": "archive"}
        os_key   = os_map.get(system, "linux")
        kind     = kind_map.get(system, "archive")

        file_info = next(
            (f for f in latest["files"]
             if f["os"] == os_key and f["arch"] == arch and f["kind"] == kind),
            None
        )
        if file_info is None:
            raise ValueError("No matching file found in release list")

        filename     = file_info["filename"]
        download_url = f"https://go.dev/dl/{filename}"

    except Exception as exc:
        print(f"  Could not fetch Go release info: {exc}")
        print("  Download Go manually from https://go.dev/dl/")
        sys.exit(1)

    if not _prompt(f"  Go {ver_str} available. Download installer? [Y/n]: "):
        print("  Download manually: https://go.dev/dl/")
        sys.exit(1)

    tmp  = tempfile.mkdtemp()
    dest = os.path.join(tmp, filename)
    _download(download_url, dest)

    if not _prompt(f"  Downloaded: {dest}\n  Launch installer now? [Y/n]: "):
        print(f"  Run manually: {dest}")
        sys.exit(1)

    if system == "Linux":
        _install_go_linux(dest)
    else:
        _launch_file(dest)
        print(f"\n  Go {ver_str} installer launched.")
        print("  After installation completes, re-run install.py to continue setup.")
        sys.exit(0)


def _install_go_linux(tarball: str):
    """Extract Go tarball to /usr/local on Linux (requires sudo)."""
    print("  Installing Go to /usr/local/go (requires sudo)...")
    result = subprocess.run(
        ["sudo", "tar", "-C", "/usr/local", "-xzf", tarball]
    )
    if result.returncode != 0:
        print("  Extraction failed. Try manually:")
        print(f"    sudo tar -C /usr/local -xzf {tarball}")
        sys.exit(1)

    print("  Go installed to /usr/local/go  \u2713")
    print()
    print("  Add Go to your PATH by appending this line to ~/.bashrc or ~/.profile:")
    print('    export PATH=$PATH:/usr/local/go/bin')
    print()
    print("  Then reload:  source ~/.bashrc")
    print("  Then re-run:  python3 install.py")
    sys.exit(0)


# ── Step 3: Create venv ───────────────────────────────────────────────────────

def create_venv():
    if os.path.exists(VENV_PYTHON):
        print("[Setup] venv    ... already exists, skipping")
        return
    print("[Setup] venv    ... creating")
    venv.create(VENV_DIR, with_pip=True)
    print("[Setup] venv    ... created  \u2713")


# ── Step 4: Install Python packages ──────────────────────────────────────────

def install_packages():
    print("[Setup] pip     ... upgrading")
    subprocess.run(
        [VENV_PYTHON, "-m", "pip", "install", "--upgrade", "pip", "--quiet"],
        check=True,
    )
    print("[Setup] packages... installing from requirements.txt")
    subprocess.run(
        [VENV_PYTHON, "-m", "pip", "install", "-r", REQ_FILE],
        check=True,
    )
    print("[Setup] packages... done  \u2713")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  VA Scanner \u2014 Setup")
    print("=" * 60)
    print()

    check_python()
    check_go()
    print()

    create_venv()
    install_packages()

    print()
    print("=" * 60)
    print("  Setup complete!")
    print()
    if IS_WINDOWS:
        print("  Run:  python start.py")
    else:
        print("  Run:  python3 start.py")
    print("=" * 60)


if __name__ == "__main__":
    main()
