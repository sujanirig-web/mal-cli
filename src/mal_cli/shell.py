"""
Interactive shell for mal-cli.

A Claude-style full-screen terminal UI:
  - Top: scrollable session/output pane (typed commands + results)
  - Bottom: input bar with syntax styling, autocomplete and history
  - Status toolbar showing device/database state
"""

import sys
import json
from pathlib import Path
from typing import List, Optional

from prompt_toolkit import Application
from prompt_toolkit.application import get_app
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.formatted_text import HTML, to_formatted_text
from prompt_toolkit.history import FileHistory
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout
from prompt_toolkit.layout.containers import (
    Float, FloatContainer, HSplit, Window,
    WindowAlign,
)
from prompt_toolkit.layout.controls import FormattedTextControl, BufferControl
from prompt_toolkit.layout.dimension import Dimension
from prompt_toolkit.styles import Style

from mal_cli import __version__
from mal_cli.adb.client import ADBClient
from mal_cli.adb.devices import DeviceManager
from mal_cli.scanner.packages import PackageScanner
from mal_cli.analyzer.analyzer import Analyzer
from mal_cli.database.database import Database
from mal_cli.monitor.monitor import Monitor
from mal_cli.output.terminal import Terminal
from mal_cli.remediation.disable import Disabler
from mal_cli.remediation.uninstall import Uninstaller
from mal_cli.remediation.quarantine import QuarantineManager

# ------------------------------------------------------------
# Settings
# ------------------------------------------------------------
CONFIG_DIR = Path.home() / ".mal_cli"
CONFIG_FILE = CONFIG_DIR / "config.json"


def load_config():
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {}


def save_config(config):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


# ------------------------------------------------------------
# Custom Completer
# ------------------------------------------------------------
class MalCliCompleter(Completer):
    def __init__(self, commands: List[str], package_names: List[str]):
        self.commands = commands
        self.package_names = package_names

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        if ' ' in text:
            cmd, args = text.split(' ', 1)
            args = args.lstrip()
            if cmd in ('info', 'history', 'disable', 'uninstall', 'quarantine'):
                for pkg in self.package_names:
                    if pkg.startswith(args):
                        yield Completion(pkg, start_position=-len(args))
            elif cmd in ('report',):
                for fmt in ('json', 'yaml', 'text'):
                    if fmt.startswith(args):
                        yield Completion(fmt, start_position=-len(args))
        else:
            for cmd in self.commands:
                if cmd.startswith(text):
                    yield Completion(cmd, start_position=-len(text))


# ------------------------------------------------------------
# Shell class
# ------------------------------------------------------------
class MalCliShell:
    def __init__(self, client: ADBClient, device, db: Database, analyzer: Analyzer):
        self.client = client
        self.device = device          # may be None initially
        self.db = db
        self.analyzer = analyzer
        self.scanner = None           # created once we have a device
        self.config = load_config()

        self.commands = [
            "devices", "apps", "info", "scan", "monitor",
            "events", "history", "disable", "uninstall",
            "quarantine", "report", "settings", "help", "clear", "exit", "quit"
        ]
        self.package_names = []

        # Output pane lines (rendered as formatted text)
        self.output = []   # list of styled (style, text) tuples
        self.output_frag = FormattedTextControl(text=[], show_cursor=False)

        # History file
        history_file = CONFIG_DIR / "history"
        history_file.parent.mkdir(parents=True, exist_ok=True)
        self.history = FileHistory(str(history_file))

        self.completer = MalCliCompleter(self.commands, self.package_names)

        self._style = Style.from_dict({
            'app-header':      '#00ff00 bold',
            'prompt':          '#00ff00 bold',
            'user':            '#00aaff bold',
            'output':          '#cccccc',
            'output.info':     '#00aaff',
            'output.ok':       '#00ff00',
            'output.warn':     '#ffaa00',
            'output.err':      '#ff5555',
            'output.head':     '#00ffff bold',
            'toolbar':         '#000000 bg:#888888',
            'toolbar.online':  '#000000 bg:#00ff00',
            'toolbar.offline':'#000000 bg:#ff5555',
            'bottom-toolbar':  'bg:#222222 #aaaaaa',
        })

        # Buffer with history + autocomplete
        self.buffer = Buffer(
            history=self.history,
            completer=self.completer,
            complete_while_typing=True,
        )
        self.buffer_control = BufferControl(
            buffer=self.buffer,
            focus_on_click=True,
        )

        self._build_layout()

    # ------------------------------------------------------------
    # Layout construction
    # ------------------------------------------------------------
    def _build_layout(self):
        header = Window(
            FormattedTextControl(
                HTML(f'<style fg="#00ff00" bg="#000000"><b> mal-cli </b></style>'
                     f'<style fg="#666666"> v{__version__} — Android security scanner</style>'),
            ),
            height=1,
            align=WindowAlign.LEFT,
        )

        output_window = Window(
            self.output_frag,
            wrap_lines=True,
            always_hide_cursor=True,
            height=Dimension(weight=1),
        )
        output_pane = output_window

        # Bottom toolbar (refresh state each render)
        def get_toolbar():
            if self.device and self.device.is_online:
                dev_info = f"{self.device.serial} ({self.device.model})"
                pkg_count = len(self.package_names) if self.package_names else 0
                dev_style = 'class:toolbar.online'
                label = '● ONLINE'
            else:
                dev_info = "no device"
                pkg_count = 0
                dev_style = 'class:toolbar.offline'
                label = '○ OFFLINE'
            return to_formatted_text([
                (f'class:toolbar', ' ▍'),
                (f'{dev_style}', f' {label} '),
                ('class:toolbar', f' {dev_info} '),
                ('class:toolbar', f'│ packages: {pkg_count} '),
                ('class:toolbar', f'│ db: {self.db.db_path} '),
                ('class:toolbar', f'│ {len(self.output)} lines'),
            ])

        # Input field with a floating "❯" prompt marker
        input_window = Window(
            self.buffer_control,
            height=1,
            wrap_lines=False,
            always_hide_cursor=False,
        )
        prompt_marker = Window(
            FormattedTextControl(to_formatted_text([('class:prompt', '❯ ')])),
            width=2,
            align=WindowAlign.RIGHT,
            dont_extend_width=True,
        )
        input_row = FloatContainer(
            content=input_window,
            floats=[Float(left=0, top=0, transparent=True, content=prompt_marker)],
        )

        toolbar_window = Window(
            FormattedTextControl(get_toolbar, style='class:toolbar'),
            height=1,
        )

        container = HSplit([
            header,
            output_pane,
            toolbar_window,
            input_row,
        ])

        # Key bindings
        kb = KeyBindings()

        @kb.add('enter')
        def _(event):
            self._dispatch(self.buffer.text)
            self.buffer.reset()

        @kb.add('c-c')
        def _(event):
            event.app.exit()

        @kb.add('c-d')
        def _(event):
            event.app.exit()

        self.app = Application(
            layout=Layout(container, focused_element=input_window),
            key_bindings=kb,
            style=self._style,
            full_screen=True,
            mouse_support=False,
            refresh_interval=0.2,
        )

        # Initial banner
        self._banner()

    # ------------------------------------------------------------
    # Output helpers
    # ------------------------------------------------------------
    def _append(self, style, text: str):
        for line in text.splitlines():
            self.output.append((style, line))
        self._refresh_output()

    @staticmethod
    def _resolve_style(style: str) -> str:
        """Prefix a bare class name with 'class:' so prompt_toolkit treats it
        as a named style rather than an inline color string. Inline style
        strings (those starting with namespaces like 'fg:', 'bg:', 'bold',
        '#hex', or already 'class:') are returned unchanged."""
        if not style or ':' in style:
            return style
        return 'class:' + style

    def _refresh_output(self):
        # Trim to a reasonable number of lines
        if len(self.output) > 4000:
            self.output = self.output[-3000:]
        frags = []
        # Render prompt glyph for user lines vs plain output.
        # Unprefixed styles (e.g. "output.head") must become class refs so
        # prompt_toolkit resolves them against our Style dict instead of
        # treating them as inline color names.
        for style, line in self.output:
            frags.append((self._resolve_style(style), line))
            frags.append(('', '\n'))
        if frags:
            frags.pop()  # remove trailing newline
        self.output_frag.text = frags

    def _banner(self):
        self.output = []
        self._append('output.head', 'mal-cli ' + __version__)
        self._append('output', 'Android security scanner & live monitor (via ADB)')
        self._append('output', '')
        self._append('output', '  Type "help" for commands, "settings" to adjust options.')
        self._append('output', '  Press Ctrl+C / Ctrl+D or type "exit" to quit.')
        self._append('output', '')

    def _print(self, text: str = ""):
        self._append('output', text)

    def _info(self, text: str):
        self._append('output.info', text)

    def _ok(self, text: str):
        self._append('output.ok', text)

    def _warn(self, text: str):
        self._append('output.warn', text)

    def _err(self, text: str):
        self._append('output.err', text)

    def _head(self, text: str):
        self._append('output.head', '▍' + text)

    # ------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------
    def _dispatch(self, line: str):
        line = line.strip()
        if not line:
            return
        self._append('class:user', '❯ ' + line)
        parts = line.split()
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd in ("exit", "quit"):
            get_app().exit()
        elif cmd == "help":
            self._show_help()
        elif cmd == "clear":
            self.output = []
            self._refresh_output()
        elif cmd == "settings":
            self._settings_menu()
        elif cmd == "devices":
            self.do_devices()
        elif cmd == "apps":
            self.do_apps()
        elif cmd == "info":
            self.do_info(arg)
        elif cmd == "scan":
            self.do_scan(arg)
        elif cmd == "monitor":
            self.do_monitor()
        elif cmd == "events":
            self.do_events(arg)
        elif cmd == "history":
            self.do_history(arg)
        elif cmd == "disable":
            self.do_disable(arg)
        elif cmd == "uninstall":
            self.do_uninstall(arg)
        elif cmd == "quarantine":
            self.do_quarantine(arg)
        elif cmd == "report":
            self.do_report(arg)
        else:
            self._err(f"Unknown command: {cmd}. Type help.")

    # ------------------------------------------------------------
    # Lazy device initialisation
    # ------------------------------------------------------------
    def _ensure_device(self) -> bool:
        if self.device is not None and self.device.is_online:
            return True
        dev_mgr = DeviceManager(self.client)
        devices = dev_mgr.list_devices()
        online = [d for d in devices if d.is_online]
        if not online:
            self._err("No online devices found. Connect a device with USB debugging enabled.")
            return False
        if len(online) == 1:
            self.device = online[0]
            self._ok(f"Auto-selected device: {self.device.serial}")
        else:
            self._info("Multiple devices found:")
            for i, d in enumerate(online):
                self._print(f"  {i+1}. {d.serial} ({d.model})")
            choice = self._prompt_str("Select device number: ")
            try:
                idx = int(choice) - 1
                self.device = online[idx]
            except (ValueError, IndexError):
                self._err("Invalid selection.")
                return False
        self.scanner = PackageScanner(self.client, self.device)
        self._refresh_package_names()
        return True

    def _refresh_package_names(self):
        if self.scanner:
            try:
                pkgs = self.scanner.get_all_packages()
                self.package_names = [p.name for p in pkgs]
                self.completer = MalCliCompleter(self.commands, self.package_names)
                self.buffer.completer = self.completer
            except Exception:
                self.package_names = []

    # Simple blocking text input (used for settings prompts)
    def _prompt_str(self, label: str) -> str:
        return input(label)

    # ------------------------------------------------------------
    # Command implementations
    # ------------------------------------------------------------
    def _render_table(self, headers, rows, colorize_risk=False):
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    col_widths[i] = max(col_widths[i], len(str(cell)))
        header_line = "  ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
        self._head(' ' + header_line)
        self._append('output', "  " + "  ".join("-" * w for w in col_widths))
        for row in rows:
            cells = []
            for i, cell in enumerate(row):
                text = str(cell)
                style = 'output'
                if colorize_risk and i == 2:
                    if "CRITICAL" in text:
                        style = 'output.err'
                    elif "HIGH" in text:
                        style = 'output.warn'
                    elif "MEDIUM" in text:
                        style = 'output.info'
                    else:
                        style = 'output.ok'
                cells.append((style, text.ljust(col_widths[i])))
            self.output.extend(cells)
            self._refresh_output()

    def do_devices(self):
        dev_mgr = DeviceManager(self.client)
        devices = dev_mgr.list_devices()
        if not devices:
            self._info("No ADB devices found.")
            return
        self._render_table(
            ["Serial", "Model", "Android", "Status"],
            [(d.serial, d.model, d.android_version, "online" if d.is_online else "offline") for d in devices]
        )

    def do_apps(self):
        if not self._ensure_device():
            return
        self._info("Fetching installed packages...")
        packages = self.scanner.get_all_packages()
        rows = []
        for pkg in packages:
            risk = self.db.get_latest_risk(pkg.name)
            if risk:
                level, score = risk["level"], risk["score"]
            else:
                level, score = "UNKNOWN", "?"
            rows.append((pkg.name, pkg.version, level, score))
        if not rows:
            self._info("No packages found.")
            return
        self._append('output', '')
        self._render_table(
            ["Package", "Version", "Risk Level", "Score"],
            rows,
            colorize_risk=True
        )

    def do_info(self, package):
        if not package:
            self._err("Usage: info <package>")
            return
        if not self._ensure_device():
            return
        pkg = self.scanner.get_package_info(package)
        if not pkg:
            self._err(f"Package '{package}' not found")
            return
        self._head(f" Package: {pkg.name}")
        self._print(f"  Version     : {pkg.version}")
        self._print(f"  Installer   : {pkg.installer or 'unknown'}")
        self._print(f"  Target SDK  : {pkg.target_sdk}")
        self._print(f"  Min SDK     : {pkg.min_sdk}")
        self._print(f"  APK Hash    : {pkg.apk_hash or 'not computed'}")
        self._print(f"  Signer      : {pkg.signer_info or 'unknown'}")
        self._info("  Permissions:")
        perms = self.db.get_permissions(pkg.name) or pkg.permissions or []
        if perms:
            for perm in perms:
                self._print(f"    {perm}")
        else:
            self._print("    (none)")
        self._info("  Services:")
        services = self.db.get_services(pkg.name) or pkg.services or []
        if services:
            for svc in services:
                self._print(f"    {svc}")
        else:
            self._print("    (none)")
        self._info("  Risk History:")
        history = self.db.get_risk_history(pkg.name, limit=10)
        if history:
            self._render_table(
                ["Timestamp", "Score", "Level"],
                [(h["timestamp"], h["score"], h["level"]) for h in history]
            )
        else:
            self._print("    No history")

    def do_scan(self, package):
        if not self._ensure_device():
            return
        if package:
            pkg = self.scanner.get_package_info(package)
            if not pkg:
                self._err(f"Package '{package}' not found")
                return
            pkgs = [pkg]
        else:
            self._info("Scanning all packages...")
            pkgs = self.scanner.get_all_packages()
        for pkg in pkgs:
            risk = self.analyzer.evaluate_package(pkg)
            self.db.save_risk(pkg.name, risk.score, risk.level, risk.explanation)
            line = f"  {pkg.name}: {risk.level} ({risk.score}) - {risk.explanation}"
            if "CRITICAL" in risk.level or "HIGH" in risk.level:
                self._warn(line)
            elif "MEDIUM" in risk.level:
                self._info(line)
            else:
                self._ok(line)
        self._ok("Scan complete.")
        self._refresh_package_names()

    def do_monitor(self):
        if not self._ensure_device():
            return
        self._info("Starting live monitor (press Ctrl+C to return to shell)...")
        self.app.exit()
        monitor = Monitor(self.client, self.device, self.db, self.analyzer, interval=2.0)
        try:
            monitor.start()
        except KeyboardInterrupt:
            monitor.stop()
            self._print("Monitoring stopped.")
        self._run_shell()

    def do_events(self, limit_str):
        limit = int(limit_str) if limit_str and limit_str.isdigit() else 20
        events = self.db.get_events(limit=limit)
        if not events:
            self._info("No events recorded.")
            return
        self._render_table(
            ["Timestamp", "Package", "Event", "Description"],
            [(e["timestamp"], e["package_name"], e["event_type"], e["description"]) for e in events]
        )

    def do_history(self, package):
        if not package:
            self._err("Usage: history <package>")
            return
        history = self.db.get_risk_history(package)
        if not history:
            self._print(f"No history for {package}")
        else:
            self._head(f" Risk History for {package}")
            self._render_table(
                ["Timestamp", "Score", "Level"],
                [(h["timestamp"], h["score"], h["level"]) for h in history]
            )

    def do_disable(self, package):
        if not package:
            self._err("Usage: disable <package>")
            return
        if not self._ensure_device():
            return
        disabler = Disabler(self.client, self.device, self.db)
        disabler.disable(package)

    def do_uninstall(self, package):
        if not package:
            self._err("Usage: uninstall <package>")
            return
        if not self._ensure_device():
            return
        uninstaller = Uninstaller(self.client, self.device, self.db)
        uninstaller.uninstall(package)

    def do_quarantine(self, package):
        if not package:
            self._err("Usage: quarantine <package>")
            return
        if not self._ensure_device():
            return
        qm = QuarantineManager(self.client, self.device, self.db)
        qm.quarantine(package)

    def do_report(self, fmt):
        from mal_cli.output.report import ReportGenerator
        gen = ReportGenerator(self.db)
        data = gen.generate()
        fmt = fmt or "text"
        if fmt == "json":
            import json as _json
            self._print(_json.dumps(data, indent=2))
        elif fmt == "yaml":
            try:
                import yaml
                self._print(yaml.dump(data))
            except ImportError:
                self._err("PyYAML not installed. Install with: pip install pyyaml")
        else:
            self._print(gen.text_report())

    def _show_help(self):
        self._head(" mal-cli Commands")
        self._print("  devices            list connected ADB devices")
        self._print("  apps               list installed packages with risk levels")
        self._print("  info <package>     show static/dynamic info for a package")
        self._print("  scan [package]     run a one-time security scan")
        self._print("  monitor            start live monitoring dashboard (Ctrl+C to stop)")
        self._print("  events [limit]     show recent security events")
        self._print("  history <package>  show risk history for a package")
        self._print("  disable <package>  disable a package")
        self._print("  uninstall <pkg>    uninstall a package")
        self._print("  quarantine <pkg>   backup APK and disable (quarantine)")
        self._print("  report [fmt]       generate a report (json|yaml|text)")
        self._print("  settings           open settings menu")
        self._print("  clear              clear the output pane")
        self._print("  help               show this help")
        self._print("  exit / quit        quit the shell")
        self._print("")
        self._info("Tip: press Tab to autocomplete packages and commands.")

    def _settings_menu(self):
        self._head(" Settings")
        self._print("  1. Default device")
        self._print("  2. Scan depth (quick/full)")
        self._print("  3. Monitor update interval")
        self._print("  4. Back")
        choice = self._prompt_str("  Select option (1-4): ").strip()
        if choice == "1":
            dev_mgr = DeviceManager(self.client)
            devices = dev_mgr.list_devices()
            online = [d for d in devices if d.is_online]
            if not online:
                self._print("  No online devices found.")
                return
            for i, d in enumerate(online):
                self._print(f"  {i+1}. {d.serial} ({d.model})")
            sel = self._prompt_str("  Choose device number: ")
            try:
                idx = int(sel) - 1
                self.config["default_device"] = online[idx].serial
                save_config(self.config)
                self._ok(f"  Default device set to {online[idx].serial}")
                self.device = online[idx]
                self.scanner = PackageScanner(self.client, self.device)
                self._refresh_package_names()
            except (ValueError, IndexError):
                self._err("  Invalid selection.")
        elif choice == "2":
            depth = self._prompt_str("  Scan depth (quick/full): ").strip().lower()
            if depth in ("quick", "full"):
                self.config["scan_depth"] = depth
                save_config(self.config)
                self._ok(f"  Scan depth set to {depth}")
        elif choice == "3":
            interval = self._prompt_str("  Monitor update interval (seconds): ").strip()
            try:
                val = float(interval)
                self.config["monitor_interval"] = val
                save_config(self.config)
                self._ok(f"  Monitor interval set to {val}s")
            except ValueError:
                self._err("  Invalid number.")
        else:
            self._print("  OK.")

    # ------------------------------------------------------------
    # Entry
    # ------------------------------------------------------------
    def run(self):
        self._run_shell()

    def _run_shell(self):
        try:
            self.app.run()
        except KeyboardInterrupt:
            pass


def main():
    client = ADBClient()
    db = Database()
    analyzer = Analyzer(db)
    shell = MalCliShell(client, None, db, analyzer)
    shell.run()


if __name__ == "__main__":
    main()
