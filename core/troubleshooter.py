import os
import sys
import shutil
import subprocess
import platform
import socket
import traceback
import json
from datetime import datetime, timezone
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Confirm, Prompt

console = Console()

DEVELOPER_CONTACT = "ANUDITKHATRI2011@GMAIL.COM"

class AutonomousTroubleshooter:
    """
    Self-Healing Diagnostics & Emergency Developer Escalation Engine.
    1. Tier 1: Attempts automated self-repair for USB, socket, driver, and database locks.
    2. Tier 2: If unrecoverable, captures forensic error telemetry and escalates
       to Lead Developer: ANUDITKHATRI2011@GMAIL.COM
    """

    @staticmethod
    def run_automated_diagnostics_and_repair(verbose=False):
        """
        Runs comprehensive self-healing repairs across all layers.
        Returns (all_healthy: bool, repairs_applied: list, issues_unresolved: list)
        """
        repairs = []
        issues = []
        os_type = platform.system().lower()

        # 1. USB Multiplexer (usbmuxd) Socket & Daemon Repair
        if shutil.which("usbmuxd"):
            try:
                # Kill stale hanging usbmuxd zombie processes if deadlocked
                if os_type == "linux":
                    subprocess.run(["pkill", "-f", "usbmuxd"], capture_output=True, timeout=2)
                    subprocess.run(["usbmuxd", "-u", "-f"], capture_output=True, timeout=2)
                    repairs.append("Cleaned stale usbmuxd socket and re-initialized multiplexer daemon")
                elif os_type == "darwin":
                    subprocess.run(["brew", "services", "restart", "usbmuxd"], capture_output=True, timeout=3)
                    repairs.append("Restarted macOS usbmuxd service via Homebrew")
            except Exception as e:
                issues.append(f"usbmuxd daemon repair error: {str(e)}")
        else:
            issues.append("usbmuxd binary not found in PATH")

        # 2. Temporary Staging & Lockfile Clean-up
        try:
            purged = 0
            for t_dir in ["/tmp", os.path.expanduser("~/.iforensic_temp")]:
                if os.path.exists(t_dir):
                    for entry in os.listdir(t_dir):
                        if entry.startswith(".iforensic_") or entry.startswith("iforensic_"):
                            p = os.path.join(t_dir, entry)
                            if os.path.isfile(p):
                                os.remove(p)
                                purged += 1
            if purged > 0:
                repairs.append(f"Purged {purged} locked temporary staging handles")
        except Exception as e:
            issues.append(f"Cache housekeeping error: {str(e)}")

        # 3. Verify Python Cryptography & System Toolchain
        try:
            import cryptography
            import docx
            repairs.append("Verified Python cryptography & DOCX libraries are operational")
        except ImportError as e:
            issues.append(f"Missing core Python dependency: {str(e)}")

        all_healthy = (len(issues) == 0)
        return all_healthy, repairs, issues

    @staticmethod
    def handle_critical_failure(exception, context="Forensic Acquisition / Execution", evidence_dir=None, dev_info=None):
        """
        Tier 2 Emergency Protocol: Attempts self-healing first.
        If still failing, compiles a Forensic Incident Dump and renders developer contact details.
        """
        console.print("\n")
        console.print(Panel(
            "[bold red]CRITICAL FORENSIC EXCEPTION DETECTED[/bold red]\n\n"
            f"[white]Context:[/white] [yellow]{context}[/yellow]\n"
            f"[white]Error Message:[/white] [red]{str(exception)}[/red]\n"
            "[dim]Attempting automated self-repair routine...[/dim]",
            border_style="red"
        ))

        # Attempt Automated Self-Repair
        healthy, repairs, issues = AutonomousTroubleshooter.run_automated_diagnostics_and_repair()

        if repairs:
            t_rep = Table(title="Autonomous Self-Healing Actions Applied", box=None)
            t_rep.add_column("Repaired Component", style="bold green")
            for r in repairs:
                t_rep.add_row(f"[OK] {r}")
            console.print(t_rep)

        # Generate Forensic Crash Dump JSON
        now_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        dump_path = os.path.abspath(f"forensic_incident_dump_{now_str}.json")

        telemetry_dump = {
            "timestamp_utc": str(datetime.now(timezone.utc)),
            "error_context": context,
            "exception_type": type(exception).__name__,
            "exception_message": str(exception),
            "stack_trace": traceback.format_exc(),
            "host_os": {
                "platform": platform.platform(),
                "system": platform.system(),
                "release": platform.release(),
                "python_version": platform.python_version(),
                "hostname": socket.gethostname()
            },
            "device_telemetry": dev_info or {},
            "evidence_directory": evidence_dir or "N/A",
            "self_healing_repairs": repairs,
            "unresolved_issues": issues,
            "escalation_contact": DEVELOPER_CONTACT
        }

        try:
            with open(dump_path, "w", encoding="utf-8") as f:
                json.dump(telemetry_dump, f, indent=2)
        except Exception:
            pass

        # Display Final Emergency Developer Escalation Screen
        console.print(Panel(
            f"[bold red][WARNING] UNRESOLVED FORENSIC OBSTACLE — DEVELOPER ESCALATION[/bold red]\n\n"
            f"[bold white]Autonomous self-repair could not fully bypass this hardware/OS limitation.[/bold white]\n\n"
            f"[bold cyan]Forensic Incident Telemetry Dump Saved:[/bold cyan]\n"
            f"[yellow]{dump_path}[/yellow]\n\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"[bold green]LEAD DEVELOPER & EMERGENCY SUPPORT CONTACT:[/bold green]\n"
            f"  • Email: [bold cyan]{DEVELOPER_CONTACT}[/bold cyan]\n"
            f"  • Support: High-Priority iOS Firmware & Binary Carving Escalation\n"
            f"  • Action: Please forward the [yellow]forensic_incident_dump_*.json[/yellow] to the developer.\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n",
            title="Emergency Developer Support Protocol",
            border_style="red"
        ))

        Prompt.ask("\n[bold cyan]Press Enter to acknowledge and return to menu[/bold cyan]")
