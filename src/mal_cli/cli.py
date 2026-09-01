#!/usr/bin/env python3
"""
Command-line interface for mal-cli.
"""

import argparse
import sys
from typing import Optional

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


def get_device(client: ADBClient, device_arg: Optional[str] = None):
    """Helper to get device, raising error if none."""
    dev_mgr = DeviceManager(client)
    return dev_mgr.get_device(device_arg)


def main(argv: Optional[list] = None) -> None:
    parser = argparse.ArgumentParser(
        description="mal-cli - Android security scanner and live monitor",
        epilog="Run 'mal-cli <command> --help' for more information."
    )
    parser.add_argument("--device", help="ADB device serial to target")
    parser.add_argument("--version", action="store_true", help="Show version and exit")

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # --- all subparsers ---
    subparsers.add_parser("devices", help="List connected ADB devices")
    apps_parser = subparsers.add_parser("apps", help="List installed packages with risk")
    apps_parser.add_argument("--filter", help="Filter package names by substring")
    info_parser = subparsers.add_parser("info", help="Show detailed info for a package")
    info_parser.add_argument("package", help="Package name")
    scan_parser = subparsers.add_parser("scan", help="Perform a one-time security scan")
    scan_parser.add_argument("--package", help="Scan only a specific package")
    monitor_parser = subparsers.add_parser("monitor", help="Start live monitoring dashboard")
    monitor_parser.add_argument("--interval", type=float, default=2.0, help="Update interval (seconds)")
    events_parser = subparsers.add_parser("events", help="Show recent security events")
    events_parser.add_argument("--limit", type=int, default=20, help="Number of events to show")
    history_parser = subparsers.add_parser("history", help="Show historical risk scores")
    history_parser.add_argument("package", nargs="?", help="Package name (omit for all)")
    report_parser = subparsers.add_parser("report", help="Generate a report")
    report_parser.add_argument("--format", choices=["json", "yaml", "text"], default="text")
    report_parser.add_argument("--output", help="Output file (default: stdout)")
    disable_parser = subparsers.add_parser("disable", help="Disable a package")
    disable_parser.add_argument("package", help="Package name")
    disable_parser.add_argument("--force", action="store_true", help="Force disable system packages")
    uninstall_parser = subparsers.add_parser("uninstall", help="Uninstall a package")
    uninstall_parser.add_argument("package", help="Package name")
    uninstall_parser.add_argument("--force", action="store_true", help="Force uninstall system packages")
    quarantine_parser = subparsers.add_parser("quarantine", help="Quarantine a package (backup + disable)")
    quarantine_parser.add_argument("package", help="Package name")
    quarantine_parser.add_argument("--force", action="store_true", help="Force quarantine system packages")
    shell_parser = subparsers.add_parser("shell", help="Start interactive shell")

    args = parser.parse_args(argv)

    if args.version:
        print(f"mal-cli version {__version__}")
        sys.exit(0)

    client = ADBClient()
    db = Database()
    analyzer = Analyzer(db)
    terminal = Terminal()

    # --- Commands that do NOT need a device ---
    if args.command == "devices":
        dev_mgr = DeviceManager(client)
        devices = dev_mgr.list_devices()
        terminal.print_table(
            ["Serial", "Model", "Android", "Status"],
            [(d.serial, d.model, d.android_version, "online" if d.is_online else "offline") for d in devices]
        )
        return

    if args.command == "history":
        if args.package:
            history = db.get_risk_history(args.package)
            if not history:
                terminal.print(f"No history for {args.package}")
                return
            terminal.print_header(f"Risk History for {args.package}")
            terminal.print_table(
                ["Timestamp", "Score", "Level"],
                [(h["timestamp"], h["score"], h["level"]) for h in history]
            )
        else:
            summaries = db.get_all_package_summaries()
            terminal.print_table(
                ["Package", "First Seen", "Last Seen", "Current Risk"],
                [(s["name"], s["first_seen"], s["last_seen"], s["current_level"]) for s in summaries]
            )
        return

    if args.command == "events":
        events = db.get_events(limit=args.limit)
        terminal.print_table(
            ["Timestamp", "Package", "Event", "Description"],
            [(e["timestamp"], e["package_name"], e["event_type"], e["description"]) for e in events]
        )
        return

    if args.command == "report":
        from mal_cli.output.report import ReportGenerator
        gen = ReportGenerator(db)
        data = gen.generate()
        if args.format == "json":
            import json
            output = json.dumps(data, indent=2)
        elif args.format == "yaml":
            try:
                import yaml
                output = yaml.dump(data)
            except ImportError:
                terminal.print_error("PyYAML not installed. Install with: pip install pyyaml")
                sys.exit(1)
        else:
            output = gen.text_report()
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
        else:
            print(output)
        return

    if args.command == "shell":
        from mal_cli.shell import MalCliShell
        # Pass no device yet – the shell will handle it lazily
        shell = MalCliShell(client, None, db, analyzer)
        shell.run()
        return

    if args.command is None:
        parser.print_help()
        return

    # --- Commands that DO need a device ---
    try:
        device = get_device(client, args.device)
    except Exception as e:
        terminal.print_error(f"Device error: {e}")
        sys.exit(1)

    if args.command == "apps":
        scanner = PackageScanner(client, device)
        packages = scanner.list_packages_light()
        rows = []
        for pkg in packages:
            risk = db.get_latest_risk(pkg.name)
            level = risk["level"] if risk else "UNKNOWN"
            score = risk["score"] if risk else "?"
            target = str(pkg.target_sdk) if pkg.target_sdk else "?"
            rows.append((pkg.name, pkg.version, level, score, target))
        terminal.print_table(
            ["Package", "Version", "Risk Level", "Score", "Target SDK"],
            rows,
            colorize_risk=True,
        )
        return

    if args.command == "info":
        scanner = PackageScanner(client, device)
        pkg = scanner.get_package_info(args.package)
        if not pkg:
            terminal.print_error(f"Package '{args.package}' not found")
            sys.exit(1)
        terminal.print_header(f"Package: {pkg.name}")
        terminal.print_key_value("Version", pkg.version)
        terminal.print_key_value("Installer", pkg.installer or "unknown")
        terminal.print_key_value("Target SDK", pkg.target_sdk)
        terminal.print_key_value("Min SDK", pkg.min_sdk)
        terminal.print_key_value("APK Hash", pkg.apk_hash or "not computed")
        terminal.print_key_value("Signer", pkg.signer_info or "unknown")
        terminal.print_subheader("Permissions")
        perms = db.get_permissions(pkg.name) or pkg.permissions or []
        for perm in perms:
            terminal.print(f"  {perm}")
        terminal.print_subheader("Services")
        services = db.get_services(pkg.name) or pkg.services or []
        for svc in services:
            terminal.print(f"  {svc}")
        terminal.print_subheader("Risk History")
        history = db.get_risk_history(pkg.name, limit=10)
        if history:
            terminal.print_table(
                ["Timestamp", "Score", "Level"],
                [(h["timestamp"], h["score"], h["level"]) for h in history]
            )
        else:
            terminal.print("  No history")
        terminal.print_subheader("Recent Events")
        events = db.get_events(pkg.name, limit=5)
        if events:
            for e in events:
                terminal.print(f"  {e['timestamp']}: {e['event_type']} - {e['description']}")
        else:
            terminal.print("  No events")
        return

    if args.command == "scan":
        scanner = PackageScanner(client, device)
        if args.package:
            pkg = scanner.get_package_info(args.package)
            if not pkg:
                terminal.print_error(f"Package '{args.package}' not found")
                sys.exit(1)
            packages = [pkg]
        else:
            packages = scanner.list_packages_light()
        results = []
        for pkg in packages:
            risk = analyzer.evaluate_package(pkg)
            level = getattr(risk.level, "value", risk.level)
            db.save_risk(pkg.name, risk.score, level, risk.explanation)
            target = str(pkg.target_sdk) if pkg.target_sdk else "?"
            results.append((pkg.name, level, risk.score, target, risk.explanation))
        terminal.print_header("Scan Results")
        terminal.print_table(
            ["Package", "Risk Level", "Score", "Target SDK", "Explanation"],
            results,
            colorize_risk=True,
            risk_col=1,
        )
        return

    if args.command == "monitor":
        monitor = Monitor(client, device, db, analyzer, interval=args.interval)
        try:
            monitor.start()
        except KeyboardInterrupt:
            monitor.stop()
            terminal.print("Monitoring stopped.")
        return

    if args.command == "disable":
        disabler = Disabler(client, device, db)
        disabler.disable(args.package, force=args.force)
        return

    if args.command == "uninstall":
        uninstaller = Uninstaller(client, device, db)
        uninstaller.uninstall(args.package, force=args.force)
        return

    if args.command == "quarantine":
        qm = QuarantineManager(client, device, db)
        qm.quarantine(args.package, force=args.force)
        return

    parser.print_help()


if __name__ == "__main__":
    main()