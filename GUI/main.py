"""
main.py — VA Scanner GUI (PyQt6)
══════════════════════════════════
Main window for the Vulnerability Assessment Scanner desktop application.

Architecture:
  ScannerGUI (QWidget)        — main window, builds all UI widgets
      └─ ScanWorker (QObject) — runs in a background QThread
             └─ api_client.start_scan_with_session()
                    └─ POST http://127.0.0.1:5500/scan

UI flow:
  1. User enters target URL + sets options (module checkboxes, page/depth limits).
  2. Clicks "Start Scan" → ScannerGUI builds a payload dict, creates ScanWorker,
     moves it to a QThread, connects signals, starts the thread.
  3. ScanWorker.run() calls start_scan_with_session() in the background thread.
     The session object is saved so cancel() can call session.close() to abort.
  4. On success  → ScanWorker.finished(result_dict) → ScannerGUI displays findings
     and enables "Open Report" buttons (xdg-open for JSON/HTML/PDF).
  5. On failure  → ScanWorker.failed(error_str)   → ScannerGUI shows error text.
  6. On cancel   → ScanWorker.cancelled()         → ScannerGUI resets UI state.

Key widgets (built in ScannerGUI):
  target_input    — URL line edit
  max_pages       — QSpinBox 1–200 (default 30)
  max_depth       — QSpinBox 1–4   (default 2)
  delay_ms        — QSpinBox 0–500 ms step 50 (default 100)
  module_checks   — dict of QCheckBox per plugin (headers/misconfig/tls/xss/sqli/cve/bac)
  format_checks   — dict of QCheckBox per report format (json/html/pdf)
  scan_btn        — Start / Cancel toggle
  log_box         — QTextEdit for real-time status messages
  report_buttons  — dynamically created "Open X" buttons after scan success
"""

import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
import urllib.request
from datetime import datetime

# Minimum password length enforced on both GUI and backend (NIST SP 800-63B / OWASP ASVS §2.1.1)
AUTH_MIN_PASSWORD_LEN = 8

# Regex patterns for credential type detection
_EMAIL_RE    = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')
_USERNAME_RE = re.compile(r'^[a-zA-Z0-9._\-]{3,}$')

import psutil

import html as _html

from PyQt6.QtCore import QEasingCurve, QObject, QPropertyAnimation, Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QCloseEvent, QTextCursor
from PyQt6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSpinBox,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from api_client import cancel_scan, health_check, logs_check, progress_check, start_scan_with_session


def _find_zap_executable():
    """
    Search well-known install paths for the OWASP ZAP launcher.

    Returns the absolute path string if found, or None if ZAP is not installed.
    Search order: fixed known paths first, then PATH (Linux only).
    """
    system = platform.system()

    if system == "Windows":
        candidates = []
        for env_var in ("ProgramFiles", "ProgramFiles(x86)"):
            base = os.environ.get(env_var, "")
            if base:
                candidates.append(os.path.join(base, "OWASP", "Zed Attack Proxy", "zap.bat"))
                candidates.append(os.path.join(base, "ZAP", "Zed Attack Proxy", "zap.bat"))
    elif system == "Darwin":
        candidates = [
            "/Applications/OWASP ZAP.app/Contents/Java/zap.sh",
        ]
    else:  # Linux / BSD
        candidates = [
            "/usr/share/zaproxy/zap.sh",
            "/opt/zaproxy/zap.sh",
        ]
        import shutil
        path_exe = shutil.which("zaproxy")
        if path_exe:
            return path_exe

    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def _zap_is_running(zap_base_url, api_key):
    """
    Probe ZAP's REST API to check whether it is already up.

    Returns True if ZAP responds with HTTP 200, False on any error.
    Endpoint: GET {zap_base_url}/JSON/core/view/version/
    """
    if api_key:
        url = f"{zap_base_url}/JSON/core/view/version/?apikey={api_key}"
    else:
        url = f"{zap_base_url}/JSON/core/view/version/"
    try:
        with urllib.request.urlopen(url, timeout=3) as resp:
            return resp.status == 200
    except Exception:
        return False


def _find_free_port():
    """Return an available TCP port on localhost by letting the OS pick one."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _find_running_zap_url(api_key=""):
    """
    Detect a ZAP daemon already running on this machine.

    Checks common ZAP ports first (fast), then scans running processes via
    psutil to catch ZAP instances started on non-standard ports.

    Returns the base URL (e.g. 'http://localhost:8880') or None.
    """
    for port in [8880, 8080, 8090]:
        url = f"http://localhost:{port}"
        if _zap_is_running(url, api_key):
            return url
    try:
        import psutil
        for proc in psutil.process_iter(["cmdline"]):
            try:
                cmdline = proc.info.get("cmdline") or []
                if any("zap" in str(a).lower() for a in cmdline):
                    for i, arg in enumerate(cmdline):
                        if arg == "-port" and i + 1 < len(cmdline):
                            p = int(cmdline[i + 1])
                            url = f"http://localhost:{p}"
                            if _zap_is_running(url, api_key):
                                return url
            except Exception:
                pass
    except Exception:
        pass
    return None


def _build_zap_launch_cmd(zap_exe, port, api_key):
    """
    Build the command list to launch ZAP in daemon mode.

    On Linux/macOS zap.sh is directly executable.
    On Windows zap.bat calls 'java' which may not be in PATH — so we read
    .install4j/inst_jre.cfg (written by the ZAP installer) to find the
    bundled JRE and invoke 'java -jar zap-*.jar' directly.
    Falls back to cmd.exe /c zap.bat if the bundled JRE is not found.
    """
    zap_args = ["-daemon", "-port", str(port)]
    if api_key:
        zap_args += ["-config", f"api.key={api_key}"]
    else:
        zap_args += ["-config", "api.disablekey=true"]

    if sys.platform != "win32":
        return [zap_exe] + zap_args  # zap.sh — directly executable on Unix

    # Windows: prefer direct java invocation to avoid PATH issues with zap.bat
    import shutil as _shutil
    java_exe = _shutil.which("java")

    if java_exe is None:
        cfg = os.path.join(os.path.dirname(zap_exe), ".install4j", "inst_jre.cfg")
        if os.path.isfile(cfg):
            with open(cfg, encoding="utf-8", errors="replace") as f:
                jre_root = f.read().strip()
            candidate = os.path.join(jre_root, "bin", "java.exe")
            if os.path.isfile(candidate):
                java_exe = candidate

    if java_exe:
        zap_dir = os.path.dirname(zap_exe)
        jars = sorted(f for f in os.listdir(zap_dir) if f.startswith("zap-") and f.endswith(".jar"))
        if jars:
            zap_jar = os.path.join(zap_dir, jars[-1])
            return [java_exe, "-Xmx512m", "-jar", zap_jar] + zap_args

    # Last resort: cmd.exe /c zap.bat (requires java in PATH)
    return ["cmd.exe", "/c", zap_exe] + zap_args


class ScanWorker(QObject):
    """
    Background worker that calls the VA Scanner backend in a separate QThread.

    Signals:
      finished(dict)  — emitted with the full ScanResponse JSON dict on success.
      failed(str)     — emitted with the error message string on exception.
      cancelled()     — emitted when cancel() was called before the response arrived.

    Cancellation:
      cancel() sets _cancelled=True and calls session.close(), which immediately
      aborts the HTTP request. The Go backend detects context cancellation and
      stops mid-scan. The QThread then exits cleanly.
    """
    finished = pyqtSignal(dict)
    failed = pyqtSignal(str)
    cancelled = pyqtSignal()
    log = pyqtSignal(str)   # thread-safe status messages → GUI output box

    def __init__(self, payload):
        super().__init__()
        self.payload = payload
        self._session = None
        self._cancelled = False
        self._zap_proc = None   # Popen handle if WE launched ZAP

    def cancel(self):
        self._cancelled = True
        # Tell the backend to stop immediately via POST /cancel.
        # This is the primary cancellation path — it cancels the Go context
        # directly, which stops all in-flight HTTP requests inside the engine.
        cancel_scan()
        # Close the session as a secondary measure so the blocked session.post()
        # in run() raises an exception and the worker thread can exit.
        if self._session is not None:
            self._session.close()

    def run(self):
        import requests

        zap_enabled = self.payload.get("options", {}).get("zap", False)
        zap_key     = self.payload.get("zap_api_key", "")

        # ── Phase 1: ZAP pre-flight ──────────────────────────────────────────
        if zap_enabled:
            # Check if ZAP is already running anywhere (common ports + psutil scan).
            # This must happen BEFORE _find_free_port() to avoid the
            # "home directory already in use" error when ZAP is active on another port.
            existing_url = _find_running_zap_url(zap_key)
            if existing_url:
                self.payload["zap_base_url"] = existing_url
                self.log.emit(f"ZAP already running — using it.")
            else:
                zap_exe = _find_zap_executable()
                if zap_exe is None:
                    self.failed.emit(
                        "ZAP Integration is enabled but OWASP ZAP was not found on this system.\n"
                        "Please install ZAP from https://www.zaproxy.org/ or uncheck ZAP Integration."
                    )
                    return

                port = str(_find_free_port())
                zap_url = f"http://localhost:{port}"
                self.payload["zap_base_url"] = zap_url
                cmd = _build_zap_launch_cmd(zap_exe, port, zap_key)

                self.log.emit(f"Starting ZAP on port {port}...")

                popen_kwargs = {"stdout": subprocess.DEVNULL, "stderr": subprocess.PIPE}
                if sys.platform == "win32":
                    popen_kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

                self._zap_proc = subprocess.Popen(cmd, **popen_kwargs)

                # ── Phase 2: Readiness poll ──────────────────────────────────
                POLL_INTERVAL = 2
                TIMEOUT = 90
                elapsed = 0
                ready = False

                while elapsed < TIMEOUT:
                    if self._cancelled:
                        self._stop_zap()
                        self.cancelled.emit()
                        return
                    if self._zap_proc.poll() is not None:
                        err = ""
                        if self._zap_proc.stderr:
                            err = self._zap_proc.stderr.read().decode(errors="replace").strip()
                        msg = f"ZAP exited (code {self._zap_proc.returncode}) during startup."
                        if err:
                            msg += f"\n{err[:500]}"
                        self.failed.emit(msg)
                        return
                    if _zap_is_running(zap_url, zap_key):
                        ready = True
                        break
                    self.log.emit(f"Waiting for ZAP... {elapsed}s")
                    time.sleep(POLL_INTERVAL)
                    elapsed += POLL_INTERVAL

                if not ready:
                    self._stop_zap()
                    self.failed.emit(
                        f"ZAP did not become ready within {TIMEOUT}s. "
                        "Try starting ZAP manually or check your installation."
                    )
                    return

                self.log.emit("ZAP ready. Proceeding with scan.")

        # ── Phase 3: Run scan ────────────────────────────────────────────────
        self._session = requests.Session()
        try:
            result = start_scan_with_session(self._session, **self.payload)
            if self._cancelled:
                self.cancelled.emit()
            else:
                self.finished.emit(result)
        except Exception as exc:
            if self._cancelled:
                self.cancelled.emit()
            else:
                self.failed.emit(str(exc))
        finally:
            # ── Phase 4: ZAP teardown ────────────────────────────────────────
            self._stop_zap()

    def _stop_zap(self):
        """Terminate the ZAP process if WE started it, then clear the handle."""
        if self._zap_proc is not None and self._zap_proc.poll() is None:
            self.log.emit("Stopping ZAP...")
            self._zap_proc.terminate()
            try:
                self._zap_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._zap_proc.kill()
                self._zap_proc.wait()
            self.log.emit("ZAP stopped.")
        self._zap_proc = None


class ScannerGUI(QWidget):
    """
    Main application window for the VA Scanner.

    Layout (top → bottom):
      _build_dashboard()       — system stats bar (CPU, RAM, scan timer)
      _build_scan_controls()   — target input, module checkboxes, report format,
                                 page/depth/delay spinboxes, Start/Cancel button
      _build_results_area()    — log output box + dynamic report open buttons

    Scan lifecycle managed by:
      _start_scan()  — validates input, builds ScanWorker, starts QThread.
      _cancel_scan() — calls ScanWorker.cancel(), waits for thread to finish.
      _on_finished() — receives result dict, renders stats/findings in log box,
                       creates "Open Report" buttons for each generated artifact.
      _on_failed()   — shows error in log box, resets button state.
    """
    def __init__(self):
        super().__init__()

        self.setWindowTitle("VA Scanner - Thesis Starter")
        self.resize(1100, 760)

        self.scan_thread = None
        self.scan_worker = None
        self.scan_running = False
        self._log_index = 0       # tracks how many backend log lines have been displayed
        self._scroll_anim = None  # QPropertyAnimation reused for smooth scrolling

        self._report_btns = []

        root = QVBoxLayout()

        self._build_dashboard(root)

        # ── Left panel: scan controls + progress bar ──────────────────────────
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 4, 0)
        self._build_scan_controls(left_layout)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setFormat("Idle")
        self.progress.setTextVisible(True)
        self.progress.setMinimumHeight(24)
        self.progress.setStyleSheet("""
            QProgressBar {
                border: 1px solid #555;
                border-radius: 4px;
                background-color: #2b2b2b;
                color: #ffffff;
                text-align: center;
                font-size: 12px;
            }
            QProgressBar::chunk {
                background-color: #e07b20;
                border-radius: 3px;
            }
        """)
        left_layout.addWidget(self.progress)
        left_layout.addStretch()

        left_scroll = QScrollArea()
        left_scroll.setWidget(left_widget)
        left_scroll.setWidgetResizable(True)
        left_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        left_scroll.setFrameShape(QFrame.Shape.NoFrame)
        left_scroll.setMinimumWidth(380)

        # ── Right panel: log output + report buttons ──────────────────────────
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #cfd8dc;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
                border: 1px solid #444;
                border-radius: 4px;
                padding: 4px;
            }
            QScrollBar:vertical {
                background: #2b2b2b;
                width: 8px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical {
                background: #555;
                border-radius: 4px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background: #e07b20;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)

        self._report_btn_row = QHBoxLayout()
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(4, 0, 0, 0)
        right_layout.addWidget(self.output)
        right_layout.addLayout(self._report_btn_row)

        # ── Horizontal splitter ───────────────────────────────────────────────
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(left_scroll)
        splitter.addWidget(right_widget)
        splitter.setSizes([440, 580])
        splitter.setChildrenCollapsible(False)
        root.addWidget(splitter, 1)

        self.status_bar = QLabel("Ready")
        self.status_bar.setStyleSheet("padding: 6px; border-top: 1px solid #444;")
        root.addWidget(self.status_bar)

        self.setLayout(root)

        self.metrics_timer = QTimer(self)
        self.metrics_timer.timeout.connect(self.update_dashboard)
        self.metrics_timer.start(1000)
        self.update_dashboard()

        self.progress_timer = QTimer(self)
        self.progress_timer.timeout.connect(self._poll_progress)

    def _build_dashboard(self, root):
        dashboard = QHBoxLayout()

        self.cpu_label = QLabel("CPU: --")
        self.ram_label = QLabel("RAM: --")
        self.backend_label = QLabel("Backend: unknown")
        self.scan_state_label = QLabel("Scan: idle")

        for widget in (self.cpu_label, self.ram_label, self.backend_label, self.scan_state_label):
            widget.setStyleSheet("padding: 6px; border: 1px solid #444; border-radius: 6px;")
            dashboard.addWidget(widget)

        root.addLayout(dashboard)

    def _build_scan_controls(self, root):
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://target.example")

        root.addWidget(QLabel("Target URL"))
        root.addWidget(self.url_input)

        # Scan mode selector
        mode_row = QHBoxLayout()
        mode_row.addWidget(QLabel("Scan Mode:"))
        self.mode_complete = QRadioButton("Complete (Pages/Depth)")
        self.mode_complete.setChecked(True)
        self.mode_timed = QRadioButton("Timed")
        self.mode_full = QRadioButton("Full Scan")
        self.mode_group = QButtonGroup()
        self.mode_group.addButton(self.mode_complete)
        self.mode_group.addButton(self.mode_timed)
        self.mode_group.addButton(self.mode_full)
        self.mode_complete.toggled.connect(self._toggle_scan_mode)
        self.mode_timed.toggled.connect(self._toggle_scan_mode)
        self.mode_full.toggled.connect(self._toggle_scan_mode)
        mode_row.addWidget(self.mode_complete)
        mode_row.addWidget(self.mode_timed)
        mode_row.addWidget(self.mode_full)
        self.full_scan_warning = QLabel("⚠ No limits — may take a very long time")
        self.full_scan_warning.setStyleSheet("color: #e07b20; font-size: 11px;")
        self.full_scan_warning.setVisible(False)
        mode_row.addWidget(self.full_scan_warning)
        mode_row.addStretch()
        root.addLayout(mode_row)

        scan_cfg = QGridLayout()
        self.lbl_max_pages = QLabel("Max Pages")
        self.max_pages = QSpinBox()
        self.max_pages.setRange(1, 200)
        self.max_pages.setValue(30)

        self.lbl_max_depth = QLabel("Max Depth")
        self.max_depth = QSpinBox()
        self.max_depth.setRange(1, 4)
        self.max_depth.setValue(2)

        self.lbl_time_limit = QLabel("Time Limit")
        self.time_limit_mins = QSpinBox()
        self.time_limit_mins.setRange(1, 120)
        self.time_limit_mins.setValue(5)
        self.time_limit_mins.setSuffix(" min")

        self.delay_ms = QSpinBox()
        self.delay_ms.setRange(0, 500)
        self.delay_ms.setSingleStep(50)
        self.delay_ms.setValue(100)
        self.delay_ms.setSuffix(" ms")

        scan_cfg.addWidget(self.lbl_max_pages, 0, 0)
        scan_cfg.addWidget(self.max_pages, 0, 1)
        scan_cfg.addWidget(self.lbl_max_depth, 0, 2)
        scan_cfg.addWidget(self.max_depth, 0, 3)
        scan_cfg.addWidget(self.lbl_time_limit, 1, 0)
        scan_cfg.addWidget(self.time_limit_mins, 1, 1)
        scan_cfg.addWidget(QLabel("Request Delay"), 2, 0)
        scan_cfg.addWidget(self.delay_ms, 2, 1)

        # Initially hide timed-mode widgets
        self.lbl_time_limit.setVisible(False)
        self.time_limit_mins.setVisible(False)

        root.addLayout(scan_cfg)

        module_layout = QGridLayout()
        self.opt_headers = QCheckBox("Headers")
        self.opt_headers.setChecked(True)
        self.opt_misconfig = QCheckBox("Misconfig")
        self.opt_misconfig.setChecked(True)
        self.opt_tls = QCheckBox("TLS")
        self.opt_tls.setChecked(True)
        self.opt_xss = QCheckBox("XSS")
        self.opt_xss.setChecked(True)
        self.opt_sqli = QCheckBox("SQLi")
        self.opt_sqli.setChecked(True)
        self.opt_cve = QCheckBox("CVE Banner")
        self.opt_cve.setChecked(True)
        self.opt_bac = QCheckBox("Broken Access Control")
        self.opt_bac.setChecked(True)
        self.opt_cmdi = QCheckBox("CMD Injection")
        self.opt_cmdi.setChecked(False)  # off by default — sends real OS commands to the target

        module_layout.addWidget(QLabel("Modules"), 0, 0)
        module_layout.addWidget(self.opt_headers, 1, 0)
        module_layout.addWidget(self.opt_misconfig, 1, 1)
        module_layout.addWidget(self.opt_tls, 1, 2)
        module_layout.addWidget(self.opt_xss, 2, 0)
        module_layout.addWidget(self.opt_sqli, 2, 1)
        module_layout.addWidget(self.opt_cve, 2, 2)
        module_layout.addWidget(self.opt_bac, 3, 0, 1, 2)
        module_layout.addWidget(self.opt_cmdi, 3, 2)
        root.addLayout(module_layout)

        zap_layout = QHBoxLayout()
        self.opt_zap = QCheckBox("ZAP Integration")
        self.opt_zap.setChecked(False)
        self.opt_zap.stateChanged.connect(self._toggle_zap_fields)
        self.zap_key = QLineEdit()
        self.zap_key.setPlaceholderText("ZAP API Key (optional)")
        self.zap_key.setEnabled(False)
        zap_layout.addWidget(self.opt_zap)
        zap_layout.addWidget(QLabel("ZAP Key"))
        zap_layout.addWidget(self.zap_key)
        zap_layout.addStretch()
        root.addLayout(zap_layout)

        # ── Authentication section ────────────────────────────────────────────
        auth_header = QHBoxLayout()
        self.opt_auth = QCheckBox("Authentication")
        self.opt_auth.setChecked(False)
        self.opt_auth.stateChanged.connect(self._toggle_auth_fields)
        auth_header.addWidget(self.opt_auth)
        auth_header.addStretch()
        root.addLayout(auth_header)

        auth_grid = QGridLayout()
        auth_grid.setContentsMargins(20, 0, 0, 4)

        # Row 0 — Login URL (spans all columns)
        auth_grid.addWidget(QLabel("Login URL"), 0, 0)
        self.auth_login_url = QLineEdit()
        self.auth_login_url.setPlaceholderText("https://target.example/login")
        auth_grid.addWidget(self.auth_login_url, 0, 1, 1, 4)

        # Row 1 — Username/Email field name + value + type indicator
        auth_grid.addWidget(QLabel("Credential Field"), 1, 0)
        self.auth_username_field = QLineEdit()
        self.auth_username_field.setPlaceholderText("username")
        auth_grid.addWidget(self.auth_username_field, 1, 1)

        auth_grid.addWidget(QLabel("Value"), 1, 2)
        self.auth_username_val = QLineEdit()
        self.auth_username_val.setPlaceholderText("Email or Username")
        self.auth_username_val.textChanged.connect(self._detect_credential_type)
        auth_grid.addWidget(self.auth_username_val, 1, 3)

        self.auth_cred_hint = QLabel("")
        self.auth_cred_hint.setMinimumWidth(80)
        self.auth_cred_hint.setStyleSheet("font-size: 11px;")
        auth_grid.addWidget(self.auth_cred_hint, 1, 4)

        # Row 2 — Password field name + value + length indicator
        auth_grid.addWidget(QLabel("Password Field"), 2, 0)
        self.auth_password_field = QLineEdit()
        self.auth_password_field.setPlaceholderText("password")
        auth_grid.addWidget(self.auth_password_field, 2, 1)

        auth_grid.addWidget(QLabel("Value"), 2, 2)
        self.auth_password_val = QLineEdit()
        self.auth_password_val.setEchoMode(QLineEdit.EchoMode.Password)
        self.auth_password_val.setPlaceholderText(f"Min {AUTH_MIN_PASSWORD_LEN} characters")
        self.auth_password_val.textChanged.connect(self._check_password_strength)
        auth_grid.addWidget(self.auth_password_val, 2, 3)

        self.auth_pass_hint = QLabel("")
        self.auth_pass_hint.setMinimumWidth(80)
        self.auth_pass_hint.setStyleSheet("font-size: 11px;")
        auth_grid.addWidget(self.auth_pass_hint, 2, 4)

        root.addLayout(auth_grid)

        # Collect auth widgets for bulk enable/disable
        self._auth_widgets = [
            self.auth_login_url,
            self.auth_username_field, self.auth_username_val,
            self.auth_password_field, self.auth_password_val,
        ]
        for w in self._auth_widgets:
            w.setEnabled(False)

        # ── Brute Force section ───────────────────────────────────────────────
        bf_header = QHBoxLayout()
        self.opt_bruteforce = QCheckBox("Brute Force Login")
        self.opt_bruteforce.setChecked(False)
        self.opt_bruteforce.stateChanged.connect(self._toggle_bruteforce_fields)
        bf_header.addWidget(self.opt_bruteforce)
        bf_header.addStretch()
        root.addLayout(bf_header)

        bf_grid = QGridLayout()
        bf_grid.setContentsMargins(20, 0, 0, 4)

        # Row 0 — Login URL (shared with auth if empty)
        bf_grid.addWidget(QLabel("Login URL"), 0, 0)
        self.bf_login_url = QLineEdit()
        self.bf_login_url.setPlaceholderText("https://target.example/login  (uses Auth Login URL if empty)")
        bf_grid.addWidget(self.bf_login_url, 0, 1, 1, 3)

        # Row 1 — Usernames list
        bf_grid.addWidget(QLabel("Usernames"), 1, 0, Qt.AlignmentFlag.AlignTop)
        self.bf_usernames = QPlainTextEdit()
        self.bf_usernames.setPlaceholderText("One username or email per line\nadmin\nuser@example.com")
        self.bf_usernames.setFixedHeight(72)
        bf_grid.addWidget(self.bf_usernames, 1, 1, 1, 2)
        # Common + Upload buttons stacked vertically in col 3
        users_btn_col = QVBoxLayout()
        users_btn_col.setSpacing(4)
        self.bf_load_users_btn = QPushButton("Common")
        self.bf_load_users_btn.setFixedWidth(70)
        self.bf_load_users_btn.setToolTip("Load common username list")
        self.bf_load_users_btn.clicked.connect(self._load_common_usernames)
        self.bf_upload_users_btn = QPushButton("Upload")
        self.bf_upload_users_btn.setFixedWidth(70)
        self.bf_upload_users_btn.setToolTip("Load usernames from .txt file")
        self.bf_upload_users_btn.clicked.connect(self._upload_usernames)
        users_btn_col.addWidget(self.bf_load_users_btn)
        users_btn_col.addWidget(self.bf_upload_users_btn)
        users_btn_col.addStretch()
        users_btn_widget = QWidget()
        users_btn_widget.setLayout(users_btn_col)
        bf_grid.addWidget(users_btn_widget, 1, 3)

        # Row 2 — Passwords list
        bf_grid.addWidget(QLabel("Passwords"), 2, 0, Qt.AlignmentFlag.AlignTop)
        self.bf_passwords = QPlainTextEdit()
        self.bf_passwords.setPlaceholderText("One password per line\npassword\n123456")
        self.bf_passwords.setFixedHeight(72)
        bf_grid.addWidget(self.bf_passwords, 2, 1, 1, 2)
        # Common + Upload buttons stacked vertically in col 3
        pass_btn_col = QVBoxLayout()
        pass_btn_col.setSpacing(4)
        self.bf_load_pass_btn = QPushButton("Common")
        self.bf_load_pass_btn.setFixedWidth(70)
        self.bf_load_pass_btn.setToolTip("Load common password list")
        self.bf_load_pass_btn.clicked.connect(self._load_common_passwords)
        self.bf_upload_pass_btn = QPushButton("Upload")
        self.bf_upload_pass_btn.setFixedWidth(70)
        self.bf_upload_pass_btn.setToolTip("Load passwords from .txt file")
        self.bf_upload_pass_btn.clicked.connect(self._upload_passwords)
        pass_btn_col.addWidget(self.bf_load_pass_btn)
        pass_btn_col.addWidget(self.bf_upload_pass_btn)
        pass_btn_col.addStretch()
        pass_btn_widget = QWidget()
        pass_btn_widget.setLayout(pass_btn_col)
        bf_grid.addWidget(pass_btn_widget, 2, 3)

        # Row 3 — Delay / Max attempts / Stop on success
        bf_grid.addWidget(QLabel("Delay"), 3, 0)
        self.bf_delay = QSpinBox()
        self.bf_delay.setRange(100, 5000)
        self.bf_delay.setSingleStep(100)
        self.bf_delay.setValue(300)
        self.bf_delay.setSuffix(" ms")
        bf_grid.addWidget(self.bf_delay, 3, 1)

        bf_grid.addWidget(QLabel("Max Attempts"), 3, 2)
        self.bf_max_attempts = QSpinBox()
        self.bf_max_attempts.setRange(1, 500)
        self.bf_max_attempts.setValue(100)
        bf_grid.addWidget(self.bf_max_attempts, 3, 3)

        # Row 4 — Stop on success + attempt count label
        self.bf_stop_on_success = QCheckBox("Stop on first success")
        self.bf_stop_on_success.setChecked(True)
        bf_grid.addWidget(self.bf_stop_on_success, 4, 1, 1, 3)

        root.addLayout(bf_grid)

        self._bf_widgets = [
            self.bf_login_url, self.bf_usernames, self.bf_passwords,
            self.bf_load_users_btn, self.bf_upload_users_btn,
            self.bf_load_pass_btn, self.bf_upload_pass_btn,
            self.bf_delay, self.bf_max_attempts, self.bf_stop_on_success,
        ]
        for w in self._bf_widgets:
            w.setEnabled(False)

        report_layout = QHBoxLayout()
        self.out_json = QCheckBox("JSON")
        self.out_json.setChecked(True)
        self.out_html = QCheckBox("HTML")
        self.out_html.setChecked(True)
        self.out_pdf = QCheckBox("PDF")
        self.out_pdf.setChecked(True)
        report_layout.addWidget(QLabel("Reports"))
        report_layout.addWidget(self.out_json)
        report_layout.addWidget(self.out_html)
        report_layout.addWidget(self.out_pdf)
        root.addLayout(report_layout)

        button_row = QHBoxLayout()
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.run_scan)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel_scan)
        button_row.addWidget(self.scan_button)
        button_row.addWidget(self.cancel_button)
        root.addLayout(button_row)

    def _toggle_scan_mode(self):
        complete = self.mode_complete.isChecked()
        timed    = self.mode_timed.isChecked()
        full     = self.mode_full.isChecked()

        self.lbl_max_pages.setVisible(complete)
        self.max_pages.setVisible(complete)
        self.lbl_max_depth.setVisible(complete)
        self.max_depth.setVisible(complete)
        self.lbl_time_limit.setVisible(timed)
        self.time_limit_mins.setVisible(timed)
        self.full_scan_warning.setVisible(full)

    def _toggle_zap_fields(self, state):
        enabled = state == Qt.CheckState.Checked.value
        self.zap_key.setEnabled(enabled)

    def _toggle_auth_fields(self, state):
        """Enable/disable all auth input widgets based on the checkbox."""
        enabled = state == Qt.CheckState.Checked.value
        for w in self._auth_widgets:
            w.setEnabled(enabled)
        if not enabled:
            self.auth_cred_hint.setText("")
            self.auth_pass_hint.setText("")

    def _detect_credential_type(self, text: str) -> None:
        """
        Real-time indicator: classify the entered value as Email or Username.

        Rules:
          Email    — matches RFC 5322 simplified pattern (contains @ + domain)
          Username — alphanumeric/._- with at least 3 characters
          Other    — shown as warning (too short or invalid format)
        """
        text = text.strip()
        if not text:
            self.auth_cred_hint.setText("")
            return
        if _EMAIL_RE.match(text):
            self.auth_cred_hint.setText("📧 Email")
            self.auth_cred_hint.setStyleSheet("color: #4fc3f7; font-size: 11px;")
        elif _USERNAME_RE.match(text):
            self.auth_cred_hint.setText("👤 Username")
            self.auth_cred_hint.setStyleSheet("color: #a5d6a7; font-size: 11px;")
        elif len(text) < 3:
            self.auth_cred_hint.setText("⚠ Too short")
            self.auth_cred_hint.setStyleSheet("color: #ffcc80; font-size: 11px;")
        else:
            self.auth_cred_hint.setText("⚠ Invalid format")
            self.auth_cred_hint.setStyleSheet("color: #ef9a9a; font-size: 11px;")

    def _check_password_strength(self, text: str) -> None:
        """
        Real-time indicator: show current length vs AUTH_MIN_PASSWORD_LEN.

        Green  — length >= AUTH_MIN_PASSWORD_LEN (meets requirement)
        Red    — length < AUTH_MIN_PASSWORD_LEN  (too short)
        """
        n = len(text)
        if n == 0:
            self.auth_pass_hint.setText("")
            return
        if n < AUTH_MIN_PASSWORD_LEN:
            self.auth_pass_hint.setText(f"{n}/{AUTH_MIN_PASSWORD_LEN} too short")
            self.auth_pass_hint.setStyleSheet("color: #ef9a9a; font-size: 11px;")
        else:
            self.auth_pass_hint.setText(f"✓ {n} chars")
            self.auth_pass_hint.setStyleSheet("color: #a5d6a7; font-size: 11px;")

    def _auth_config(self) -> dict:
        """Build the AuthConfig dict for the scan payload."""
        return {
            "enabled":        self.opt_auth.isChecked(),
            "login_url":      self.auth_login_url.text().strip(),
            "username_field": self.auth_username_field.text().strip() or "username",
            "password_field": self.auth_password_field.text().strip() or "password",
            "username":       self.auth_username_val.text().strip(),
            "password":       self.auth_password_val.text(),
        }

    # ── Brute Force helpers ───────────────────────────────────────────────────

    _COMMON_USERNAMES = [
        "admin", "administrator", "root", "user", "test", "guest",
        "demo", "info", "support", "webmaster", "operator", "manager",
    ]

    _COMMON_PASSWORDS = [
        "123456", "password", "123456789", "12345678", "12345",
        "1234567", "qwerty", "abc123", "password1", "admin",
        "iloveyou", "111111", "123123", "welcome", "monkey",
        "dragon", "master", "letmein", "login", "pass",
        "test", "000000", "admin123", "654321", "P@ssw0rd",
    ]

    def _toggle_bruteforce_fields(self, state: int) -> None:
        enabled = state == Qt.CheckState.Checked.value
        for w in self._bf_widgets:
            w.setEnabled(enabled)

    def _load_common_usernames(self) -> None:
        self.bf_usernames.setPlainText("\n".join(self._COMMON_USERNAMES))

    def _load_common_passwords(self) -> None:
        self.bf_passwords.setPlainText("\n".join(self._COMMON_PASSWORDS))

    _UPLOAD_LINE_LIMIT = 10_000  # cap เพื่อป้องกัน GUI ค้างเมื่อเปิดไฟล์ใหญ่ (เช่น rockyou.txt)

    def _upload_usernames(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Username List", "", "Text files (*.txt);;All files (*)"
        )
        if not path:
            return
        with open(path, encoding="utf-8", errors="ignore") as f:
            lines = [ln.strip() for ln in f if ln.strip()]
        truncated = len(lines) > self._UPLOAD_LINE_LIMIT
        lines = lines[: self._UPLOAD_LINE_LIMIT]
        self.bf_usernames.setPlainText("\n".join(lines))
        if truncated:
            self._append_log(
                f"[Brute Force] warning: username file truncated to {self._UPLOAD_LINE_LIMIT:,} lines"
            )

    def _upload_passwords(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Password List", "", "Text files (*.txt);;All files (*)"
        )
        if not path:
            return
        with open(path, encoding="utf-8", errors="ignore") as f:
            lines = [ln.strip() for ln in f if ln.strip()]
        truncated = len(lines) > self._UPLOAD_LINE_LIMIT
        lines = lines[: self._UPLOAD_LINE_LIMIT]
        self.bf_passwords.setPlainText("\n".join(lines))
        if truncated:
            self._append_log(
                f"[Brute Force] warning: password file truncated to {self._UPLOAD_LINE_LIMIT:,} lines"
            )

    def _brute_force_config(self) -> dict:
        usernames = [u for u in self.bf_usernames.toPlainText().splitlines() if u.strip()]
        passwords = [p for p in self.bf_passwords.toPlainText().splitlines() if p.strip()]
        return {
            "enabled":        self.opt_bruteforce.isChecked(),
            "login_url":      self.bf_login_url.text().strip(),
            "username_field": "",
            "password_field": "",
            "usernames":      usernames,
            "passwords":      passwords,
            "delay_ms":       self.bf_delay.value(),
            "stop_on_success": self.bf_stop_on_success.isChecked(),
            "max_attempts":   self.bf_max_attempts.value(),
        }

    def _module_options(self):
        return {
            "headers": self.opt_headers.isChecked(),
            "misconfig": self.opt_misconfig.isChecked(),
            "tls": self.opt_tls.isChecked(),
            "xss": self.opt_xss.isChecked(),
            "sqli": self.opt_sqli.isChecked(),
            "cve": self.opt_cve.isChecked(),
            "zap": self.opt_zap.isChecked(),
            "bac": self.opt_bac.isChecked(),
            "cmdi": self.opt_cmdi.isChecked(),
        }

    def _report_formats(self):
        formats = []
        if self.out_json.isChecked():
            formats.append("json")
        if self.out_html.isChecked():
            formats.append("html")
        if self.out_pdf.isChecked():
            formats.append("pdf")
        return formats

    def run_scan(self):
        if self.scan_running:
            return

        target = self.url_input.text().strip()
        if not target:
            self.output.setText("Please enter target URL")
            self.set_status("Validation failed: target URL is empty")
            return

        reports = self._report_formats()
        if not reports:
            self.output.setText("Please select at least one report format")
            self.set_status("Validation failed: no report format selected")
            return

        if self.opt_auth.isChecked():
            if not self.auth_login_url.text().strip():
                self.output.setText("Authentication enabled: Login URL is required")
                self.set_status("Validation failed: Login URL empty")
                return
            cred = self.auth_username_val.text().strip()
            if not cred:
                self.output.setText("Authentication enabled: Username/Email is required")
                self.set_status("Validation failed: Username empty")
                return
            if not (_EMAIL_RE.match(cred) or _USERNAME_RE.match(cred)):
                self.output.setText(
                    "Authentication enabled: Username must be a valid Email or Username (min 3 chars)"
                )
                self.set_status("Validation failed: invalid credential format")
                return
            if len(self.auth_password_val.text()) < AUTH_MIN_PASSWORD_LEN:
                self.output.setText(
                    f"Authentication enabled: Password must be at least {AUTH_MIN_PASSWORD_LEN} characters"
                )
                self.set_status("Validation failed: Password too short")
                return

        if self.opt_bruteforce.isChecked():
            bf_login = self.bf_login_url.text().strip()
            auth_login = self.auth_login_url.text().strip() if self.opt_auth.isChecked() else ""
            if not bf_login and not auth_login:
                self.output.setText("Brute Force enabled: Login URL is required (set here or in Authentication)")
                self.set_status("Validation failed: Brute Force login URL empty")
                return
            users = [u for u in self.bf_usernames.toPlainText().splitlines() if u.strip()]
            if not users:
                self.output.setText("Brute Force enabled: Usernames list must not be empty")
                self.set_status("Validation failed: no usernames")
                return
            pwords = [p for p in self.bf_passwords.toPlainText().splitlines() if p.strip()]
            if not pwords:
                self.output.setText("Brute Force enabled: Passwords list must not be empty")
                self.set_status("Validation failed: no passwords")
                return

        self.output.clear()
        self._log_index = 0
        self._append_log("Scanning... please wait")
        self.scan_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.scan_running = True
        self.scan_state_label.setText("Scan: running")
        self.progress.setRange(0, 0)
        self.progress.setFormat("Scanning...")
        self.set_status("Scan started")

        timed = self.mode_timed.isChecked()
        full  = self.mode_full.isChecked()
        payload = {
            "target": target,
            "options": self._module_options(),
            "report_formats": reports,
            "max_pages": self.max_pages.value(),
            "max_depth": self.max_depth.value(),
            "request_delay_ms": self.delay_ms.value(),
            "zap_base_url": "",  # ScanWorker.run() Phase 1 assigns the actual port
            "zap_api_key": self.zap_key.text().strip(),
            "timed_mode": timed,
            "time_limit_secs": self.time_limit_mins.value() * 60 if timed else 0,
            "full_scan_mode": full,
            "auth": self._auth_config(),
            "brute_force": self._brute_force_config(),
        }

        self.scan_thread = QThread()
        self.scan_worker = ScanWorker(payload)
        self.scan_worker.moveToThread(self.scan_thread)

        self.scan_thread.started.connect(self.scan_worker.run)
        self.scan_worker.finished.connect(self.on_scan_success)
        self.scan_worker.failed.connect(self.on_scan_failed)
        self.scan_worker.cancelled.connect(self.on_scan_cancelled)
        self.scan_worker.finished.connect(self.cleanup_scan_thread)
        self.scan_worker.failed.connect(self.cleanup_scan_thread)
        self.scan_worker.cancelled.connect(self.cleanup_scan_thread)
        self.scan_worker.log.connect(self._append_log)
        self.scan_thread.start()
        self.progress_timer.start(1000)

    def on_scan_success(self, results):
        self._append_log("Scan completed. Results below:")
        self.output.append(json.dumps(results, indent=2, ensure_ascii=False))
        count = len(results.get("findings", [])) if isinstance(results, dict) else 0
        self.set_status(f"Scan completed: {count} findings")
        self._update_report_buttons(results.get("reports", []))

    def on_scan_failed(self, error_message):
        self._append_log(f"Scan failed: {error_message}")
        self.set_status(f"Scan failed: {error_message}")

    def on_scan_cancelled(self):
        self._append_log("Scan was cancelled.")
        self.set_status("Scan cancelled.")

    def cancel_scan(self):
        if self.scan_worker is not None:
            self.scan_worker.cancel()
        self.set_status("Cancelling scan...")

    # ── Log color palette (dark theme) ───────────────────────────────────────────
    _LOG_COLORS = {
        "zap":     "#4fc3f7",   # cyan  — [ZAPScanner] lines
        "engine":  "#a5d6a7",   # green — [Engine] lines
        "error":   "#ef9a9a",   # red   — fail / error keywords
        "success": "#fff176",   # yellow— complete / ready / done / saved
        "warn":    "#ffcc80",   # orange— warning / timeout / unavailable
        "default": "#cfd8dc",   # grey-white — everything else
    }
    _LOG_TS_COLOR  = "#546e7a"  # muted blue-grey for the timestamp
    _MAX_LOG_LINES = 500        # trim oldest lines when exceeded

    def _append_log(self, message: str) -> None:
        """
        Append a color-coded, HTML-escaped, timestamped line to the output box
        and smoothly animate the scrollbar to the new bottom position.

        Color rules (first match wins):
          [ZAPScanner] → cyan
          [Engine]     → green
          fail/error   → red
          complete/done/ready/saved → yellow
          warning/timeout/unavailable → orange
          otherwise    → default grey-white
        """
        now = datetime.now().strftime("%H:%M:%S")
        escaped = _html.escape(str(message))

        msg_lower = message.lower()
        if "[ZAPScanner]" in message:
            color = self._LOG_COLORS["zap"]
        elif "[Engine]" in message:
            color = self._LOG_COLORS["engine"]
        elif any(w in msg_lower for w in ("fail", "error", "not found")):
            color = self._LOG_COLORS["error"]
        elif any(w in msg_lower for w in ("complete", "done", "ready", "saved", "success")):
            color = self._LOG_COLORS["success"]
        elif any(w in msg_lower for w in ("warning", "timeout", "unavailable")):
            color = self._LOG_COLORS["warn"]
        else:
            color = self._LOG_COLORS["default"]

        line_html = (
            f'<span style="color:{self._LOG_TS_COLOR}">[{now}]</span>'
            f'&nbsp;<span style="color:{color}">{escaped}</span>'
        )
        self.output.append(line_html)

        # Trim oldest lines once the document exceeds the limit
        doc = self.output.document()
        if doc.blockCount() > self._MAX_LOG_LINES:
            trim = QTextCursor(doc.begin())
            trim.movePosition(
                QTextCursor.MoveOperation.NextBlock,
                QTextCursor.MoveMode.KeepAnchor,
                doc.blockCount() - self._MAX_LOG_LINES,
            )
            trim.removeSelectedText()

        # Smooth-scroll to bottom using QPropertyAnimation (250 ms, ease-out)
        sb = self.output.verticalScrollBar()
        if self._scroll_anim is None:
            self._scroll_anim = QPropertyAnimation(sb, b"value", self)
            self._scroll_anim.setDuration(250)
            self._scroll_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._scroll_anim.stop()
        self._scroll_anim.setStartValue(sb.value())
        self._scroll_anim.setEndValue(sb.maximum())
        self._scroll_anim.start()

    def _poll_progress(self):
        """Poll /progress and /logs every second; update the progress bar and log box."""
        try:
            p = progress_check()
            phase = p.get("phase", "idle")
            pct = p.get("percent", 0)
            done = p.get("done", 0)
            total = p.get("total", 0)

            if phase == "crawling":
                self.progress.setRange(0, 0)
                self.progress.setFormat("Crawling...")
            elif phase == "scanning":
                self.progress.setRange(0, 100)
                self.progress.setValue(int(pct))
                label = f"Scanning {done}/{total} pages ({pct:.0f}%%)" if total > 0 else "Scanning..."
                self.progress.setFormat(label)
            elif phase == "reporting":
                self.progress.setRange(0, 100)
                self.progress.setValue(98)
                self.progress.setFormat("Generating reports... (98%%)")
        except Exception:
            pass

        # Pull new backend log lines ([Engine] / [ZAPScanner]) and display them.
        try:
            result = logs_check(self._log_index)
            for line in result.get("lines", []):
                self._append_log(line)
            self._log_index = result.get("next", self._log_index)
        except Exception:
            pass

    def _update_report_buttons(self, reports):
        for btn in self._report_btns:
            btn.setParent(None)
        self._report_btns = []
        for r in reports:
            path = r.get("path", "")
            fmt = r.get("format", "").upper()
            if not path or not os.path.exists(path):
                continue
            btn = QPushButton(f"Open {fmt}")
            btn.clicked.connect(lambda _, p=path: self._open_file(p))
            self._report_btn_row.addWidget(btn)
            self._report_btns.append(btn)

    def _open_file(self, path):
        if sys.platform == "win32":
            os.startfile(path)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])

    def cleanup_scan_thread(self):
        self.progress_timer.stop()
        self.scan_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.scan_running = False
        self.scan_state_label.setText("Scan: idle")
        self.progress.setRange(0, 100)
        self.progress.setValue(100)
        self.progress.setFormat("Done")

        if self.scan_thread is not None:
            self.scan_thread.quit()
            self.scan_thread.wait(1000)
            self.scan_thread = None
        self.scan_worker = None

    def set_status(self, message):
        now = datetime.now().strftime("%H:%M:%S")
        self.status_bar.setText(f"[{now}] {message}")

    def update_dashboard(self):
        cpu = self.read_cpu_percent()
        ram = self.read_ram_percent()

        self.cpu_label.setText(f"CPU: {cpu:.1f}%" if cpu is not None else "CPU: N/A")
        self.ram_label.setText(f"RAM: {ram:.1f}%" if ram is not None else "RAM: N/A")

        try:
            health = health_check()
            status = health.get("status", "unknown") if isinstance(health, dict) else "unknown"
            self.backend_label.setText(f"Backend: {status}")
        except Exception:
            self.backend_label.setText("Backend: down")

    def read_cpu_percent(self):
        try:
            return psutil.cpu_percent(interval=None)
        except Exception:
            return None

    def read_ram_percent(self):
        try:
            return psutil.virtual_memory().percent
        except Exception:
            return None

    def closeEvent(self, event: QCloseEvent):
        if self.scan_thread is not None and self.scan_thread.isRunning():
            self.set_status("Closing app: stopping scan worker")
            if self.scan_worker is not None:
                self.scan_worker.cancel()   # triggers _stop_zap() inside run()
            self.scan_thread.quit()
            if not self.scan_thread.wait(5000):   # 5s to allow ZAP teardown
                self.scan_thread.terminate()
                self.scan_thread.wait(500)
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ScannerGUI()
    window.show()
    sys.exit(app.exec())
