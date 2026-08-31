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
from prompt_toolkit.layout import ConditionalContainer
from prompt_toolkit.filters import Condition
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
        self.command_help = {
            "devices":     "list connected ADB devices",
            "apps":        "list packages with risk levels",
            "info":        "show info for a package",
            "scan":        "run a one-time security scan",
            "monitor":     "start live monitoring dashboard",
            "events":      "show recent security events",
            "history":     "show risk history for a package",
            "disable":     "disable a package",
            "uninstall":   "uninstall a package",
            "quarantine":  "backup APK and disable",
            "report":      "generate a report (json|yaml|text)",
            "settings":    "open settings menu",
            "help":        "show command help",
            "clear":       "clear the output pane",
            "exit":        "quit the shell",
            "quit":        "quit the shell",
        }
        self.package_names = []

        # Slash-command palette state
        self.palette_open = False
        self.palette_index = 0
        self.filtered_palette = []

        # Output pane lines (rendered as formatted text)
        self.output = []   # list of styled (style, text) tuples
        self.output_frag = FormattedTextControl(text=[], show_cursor=False)

        # History file
        history_file = CONFIG_DIR / "history"
        history_file.parent.mkdir(parents=True, exist_ok=True)
        self.history = FileHistory(str(history_file))

        self.completer = MalCliCompleter(self.commands, self.package_names)

        self._style = Style.from_dict({
            # Background surfaces
            'app-header':      '#00ff9f bold bg:#0b0f0a',
            'header-text':     '#9fe8c0 bg:#0b0f0a',
            'header-dim':      '#4a6b58 bg:#0b0f0a',
            'prompt':          '#00ff9f bold',
            'input':           '#f2ffe9',
            # Output colors
            'user':            '#32ffa7 bold',
            'output':          '#d7e8d7',
            'output.info':     '#4fc3ff',
            'output.ok':       '#2be37c',
            'output.warn':     '#ffc24b',
            'output.err':      '#ff5c5c',
            'output.head':     '#4dffc0 bold',
            'output.dim':      '#6b7f70',
            # Palette (green theme)
            'palette':         'bg:#10251a',
            'palette.border':  'bg:#10251a #3a5b46',
            'palette.name':    '#00ff9f bg:#10251a',
            'palette.desc':    '#9fe8c0 bg:#10251a',
            'palette.active':  'bg:#2be37c #06120a bold',
            # Toolbar
            'toolbar':         '#0b0f0a bg:#10251a',
            'toolbar.sep':     '#3a5b46 bg:#10251a',
            'toolbar.online':  '#06120a bg:#2be37c',
            'toolbar.offline': '#120808 bg:#ff5c5c',
            'footer':          '#4a6b58 bg:#10251a',
            'bottom-toolbar':  'bg:#0b0f0a #8fa99a',
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
                HTML(
                    f'<style fg="#00ff9f" bg="#0b0f0a"><b> ◆ mal-cli </b></style>'
                    f'<style fg="#9fe8c0" bg="#0b0f0a"> Android Security Scanner </style>'
                    f'<style fg="#4a6b58" bg="#0b0f0a">      v{__version__}</style>'
                ),
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
                (f'class:toolbar', ' '),
                (f'{dev_style}', f' {label} '),
                ('class:toolbar.sep', ' │ '),
                ('class:toolbar', f'{dev_info} '),
                ('class:toolbar.sep', '│ '),
                ('class:toolbar', f'packages: {pkg_count} '),
                ('class:toolbar.sep', '│ '),
                ('class:toolbar', f'db: {self.db.db_path} '),
                ('class:toolbar.sep', '│ '),
                ('class:toolbar', f'{len(self.output)} lines'),
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

        # Slash-command palette (Claude Code style right-hand command list)
        palette_control = FormattedTextControl(self._get_palette_text, show_cursor=False)
        palette_window = Window(
            palette_control,
            height=Dimension.exact(7),
            always_hide_cursor=True,
            wrap_lines=False,
            dont_extend_height=True,
            dont_extend_width=True,
        )
        self._palette_window = palette_window

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

        # Top-level float container so the command palette can overlay the
        # output pane just above the input bar (Claude Code style).
        root = FloatContainer(
            container,
            floats=[
                Float(right=0, bottom=1, height=7, width=46, left=None,
                      content=ConditionalContainer(
                          palette_window,
                          filter=Condition(self._palette_is_open),
                      )),
            ],
        )

        # Key bindings
        kb = KeyBindings()

        @kb.add('enter')
        def _(event):
            if self.palette_open and self.filtered_palette:
                cmd = self.filtered_palette[
                    self.palette_index % len(self.filtered_palette)
                ][0]
                self.buffer.text = cmd
                self.buffer.cursor_position = len(cmd)
                self._close_palette()
                self._run_buffer()
            else:
                self._run_buffer()

        @kb.add('up')
        def _(event):
            if self.palette_open:
                self.palette_index -= 1
                self._refresh_palette()
            else:
                event.app.current_buffer.cursor_up()

        @kb.add('down')
        def _(event):
            if self.palette_open:
                self.palette_index += 1
                self._refresh_palette()
            else:
                event.app.current_buffer.cursor_down()

        @kb.add('escape')
        def _(event):
            if self.palette_open:
                self._close_palette()
            else:
                event.app.current_buffer.reset()

        @kb.add('c-c')
        def _(event):
            if self.palette_open:
                self._close_palette()
            else:
                event.app.exit()

        @kb.add('c-d')
        def _(event):
            event.app.exit()

        self.buffer.on_text_changed += self._on_text_changed

        self.app = Application(
            layout=Layout(root, focused_element=input_window),
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
        self._append('output.head', '  mal-cli -- Android Security Scanner')
        self._append('output', '  ' + '─' * 46)
        self._append('output.dim', '  • Interactive security analysis over ADB')
        self._append('output.dim', '  • Risk scoring  |  live monitoring  |  remediation')
        self._append('output', '')
        self._append('output', '  Type "help" for commands or "settings" to adjust options.')
        self._append('output.dim', '  Press Ctrl+C / Ctrl+D or type "exit" to quit.')
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
    # Slash-command palette
    # ------------------------------------------------------------
    def _run_buffer(self):
        self._dispatch(self.buffer.text)
        self.buffer.reset()
        self._close_palette()

    def _on_text_changed(self, event=None):
        text = self.buffer.text.lstrip()
        if text.startswith('/') and len(text) > 1:
            self._open_palette()
        else:
            if self.palette_open and not text.startswith('/'):
                self._close_palette()

    def _open_palette(self):
        if self.palette_open:
            return
        self.palette_open = True
        self.palette_index = 0
        self._refresh_palette()

    def _palette_is_open(self):
        return self.palette_open

    def _close_palette(self):
        self.palette_open = False
        self._refresh_palette()

    def _refresh_palette(self):
        # Recompute the filtered command list from the buffer text after '/'
        text = self.buffer.text.lstrip()
        query = text[1:] if text.startswith('/') else ''
        if query:
            self.filtered_palette = [
                (c, self.command_help.get(c, ''))
                for c in self.commands if c.startswith(query)
            ]
        else:
            self.filtered_palette = [
                (c, self.command_help.get(c, '')) for c in self.commands
            ]
        self.palette_index = max(0, min(self.palette_index,
                                        max(0, len(self.filtered_palette) - 1)))

    def _get_palette_text(self):
        if not self.palette_open:
            return to_formatted_text([])
        if not self.filtered_palette:
            return to_formatted_text([('class:palette', '   no matching commands')])
        lines = [('class:palette.border', '   Commands')]
        for i, (name, desc) in enumerate(self.filtered_palette):
            active = (i == self.palette_index % len(self.filtered_palette))
            sty = 'class:palette.active' if active else 'class:palette'
            name_sty = 'class:palette.active' if active else 'class:palette.name'
            desc_sty = 'class:palette.active' if active else 'class:palette.desc'
            lines.append((sty, '  '))
            lines.append((name_sty, name.ljust(12)))
            lines.append((desc_sty, desc[:26]))
            lines.append(('', '\n'))
        if lines and lines[-1][1].endswith('\n'):
            lines.pop()
        return to_formatted_text(lines)

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
        self._append('output', "  ┌─" + "─┬─".join("─" * w for w in col_widths) + "─┐")
        header_line = "  │ " + " │ ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers)) + " │"
        self._head(header_line)
        self._append('output', "  ├─" + "─┼─".join("─" * w for w in col_widths) + "─┤")
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
            self.output.append(('output', "  │ "))
            self.output.extend(cells)
            self.output.append(('output', " │"))
            self._refresh_output()
        self._append('output', "  └─" + "─┴─".join("─" * w for w in col_widths) + "─┘")

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
        self._head("  mal-cli Commands")
        self._append('output', '')
        self._info("  ▸ Inspect")
        self._print("    devices            list connected ADB devices")
        self._print("    apps               list installed packages with risk levels")
        self._print("    info <package>     show static/dynamic info for a package")
        self._print("    scan [package]     run a one-time security scan")
        self._print("    monitor            start live monitoring dashboard (Ctrl+C to stop)")
        self._print("    events [limit]     show recent security events")
        self._print("    history <package>  show risk history for a package")
        self._print("    report [fmt]       generate a report (json|yaml|text)")
        self._append('output', '')
        self._info("  ▸ Remediate")
        self._print("    disable <package>  disable a package")
        self._print("    uninstall <pkg>    uninstall a package")
        self._print("    quarantine <pkg>   backup APK and disable (quarantine)")
        self._append('output', '')
        self._info("  ▸ System")
        self._print("    settings           open settings menu")
        self._print("    clear              clear the output pane")
        self._print("    help               show this help")
        self._print("    exit / quit        quit the shell")
        self._append('output', '')
        self._ok("Tip: press Tab to autocomplete packages and commands.")

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
