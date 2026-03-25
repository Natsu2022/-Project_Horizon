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
import socket
import subprocess
import sys
import time
import urllib.request
from datetime import datetime

import psutil

from PyQt6.QtCore import QObject, Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QCloseEvent
from PyQt6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from api_client import health_check, progress_check, start_scan_with_session


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
        self.resize(1040, 760)

        self.scan_thread = None
        self.scan_worker = None
        self.scan_running = False

        self._report_btns = []

        root = QVBoxLayout()

        self._build_dashboard(root)
        self._build_scan_controls(root)

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
        root.addWidget(self.progress)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        root.addWidget(self.output)

        self._report_btn_row = QHBoxLayout()
        root.addLayout(self._report_btn_row)

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

        module_layout.addWidget(QLabel("Modules"), 0, 0)
        module_layout.addWidget(self.opt_headers, 1, 0)
        module_layout.addWidget(self.opt_misconfig, 1, 1)
        module_layout.addWidget(self.opt_tls, 1, 2)
        module_layout.addWidget(self.opt_xss, 2, 0)
        module_layout.addWidget(self.opt_sqli, 2, 1)
        module_layout.addWidget(self.opt_cve, 2, 2)
        module_layout.addWidget(self.opt_bac, 3, 0, 1, 2)
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

        self.output.clear()
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

    def _append_log(self, message):
        """Append a timestamped line to the output box (slot called from worker via signal)."""
        now = datetime.now().strftime("%H:%M:%S")
        self.output.append(f"[{now}] {message}")

    def _poll_progress(self):
        """Poll /progress every second and update the progress bar (called by QTimer)."""
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
