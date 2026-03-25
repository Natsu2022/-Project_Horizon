#!/usr/bin/env python3
"""
start.py — Cross-platform launcher for VA Scanner
===================================================
Supports Windows, macOS, and Linux without any external dependencies.

Steps:
  1. Build the Go backend binary
  2. Start the backend in the background
  3. Wait for the backend to be ready (health check)
  4. Launch the PyQt6 GUI (foreground)
  5. On exit: terminate backend and clean up binary
"""

import os
import platform
import subprocess
import sys
import time
import urllib.request

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(SCRIPT_DIR, "Backend_Go")
GUI_DIR = os.path.join(SCRIPT_DIR, "GUI")

IS_WINDOWS = platform.system() == "Windows"
SERVER_BIN = os.path.join(SCRIPT_DIR, ".va-server.exe" if IS_WINDOWS else ".va-server")

_backend_proc = None


def cleanup():
    global _backend_proc
    if _backend_proc is not None and _backend_proc.poll() is None:
        print("\nStopping backend...")
        _backend_proc.terminate()
        try:
            _backend_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _backend_proc.kill()
            _backend_proc.wait()
        _backend_proc = None

    if os.path.exists(SERVER_BIN):
        try:
            os.remove(SERVER_BIN)
        except OSError:
            pass
    print("Done.")


def build_backend():
    print("[1/3] Building backend...")
    result = subprocess.run(
        ["go", "build", "-o", SERVER_BIN, "./cmd/scanner"],
        cwd=BACKEND_DIR,
    )
    if result.returncode != 0:
        print("Build failed. Check Go installation and source code.")
        sys.exit(1)
    print("      Build successful.")


def start_backend():
    global _backend_proc
    print("[2/3] Starting backend...")

    kwargs = {"cwd": SCRIPT_DIR}
    if IS_WINDOWS:
        # Hide the console window that would pop up for the backend process
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

    _backend_proc = subprocess.Popen([SERVER_BIN], **kwargs)


def wait_for_backend(max_wait: int = 15) -> bool:
    print("[3/3] Waiting for backend to be ready...")
    for attempt in range(max_wait):
        # Check if the process crashed before it became ready
        if _backend_proc.poll() is not None:
            print(f"      Backend process exited unexpectedly (code {_backend_proc.returncode}).")
            return False

        try:
            with urllib.request.urlopen("http://127.0.0.1:5500/health", timeout=1) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass

        time.sleep(1)

    return False


def find_python() -> str:
    """Return the Python executable to use, preferring the project venv."""
    if IS_WINDOWS:
        venv_python = os.path.join(SCRIPT_DIR, "venv", "Scripts", "python.exe")
    else:
        venv_python = os.path.join(SCRIPT_DIR, "venv", "bin", "python")

    if os.path.exists(venv_python):
        return venv_python
    return sys.executable


def start_gui() -> int:
    python = find_python()
    print(f"Starting GUI with: {python}")
    result = subprocess.run([python, "main.py"], cwd=GUI_DIR)
    return result.returncode


def main():
    build_backend()
    start_backend()

    if not wait_for_backend():
        print("Backend did not start in time. Exiting.")
        cleanup()
        sys.exit(1)

    print("Backend ready on http://127.0.0.1:5500\n")

    exit_code = 0
    try:
        exit_code = start_gui()
    finally:
        cleanup()

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
