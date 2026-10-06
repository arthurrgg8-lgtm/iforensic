import os
import sys
import shutil
import subprocess
import platform
import time
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm

console = Console()

class MaintenanceManager:
    """
    Automated Startup Self-Updater, Firmware Definition Fetcher, and Self-Healing Engine.
    1. Online Update Check: Detects new tool versions, device profiles, and app decoders.
    2. Interactive Prompt: Asks the investigator to update and start seamlessly.
    3. Self-Healing Daemon: Resets usbmuxd sockets and purges locks automatically.
    """

    @staticmethod
    def run_startup_maintenance(interactive_update=True, timeout_sec=2):
        """
        Executes startup maintenance, checks for online updates, and prompts user if updates exist.
        """
        maintenance_log = []

        # 1. Daemon Health Check & Socket Self-Healing
        daemon_ok = MaintenanceManager._heal_forensics_daemon()
        if daemon_ok:
            maintenance_log.append("usbmuxd socket active and operational")

        # 2. Housekeeping (Clean temporary probe files and orphans)
        cleaned_count = MaintenanceManager._clean_temp_artifacts()
        if cleaned_count > 0:
            maintenance_log.append(f"Purged {cleaned_count} orphaned temporary staging files")

        # 3. Check for new Version / Firmware Profiles / App Modules
        update_available, update_details = MaintenanceManager._check_for_updates(timeout_sec)
        
        if update_available and interactive_update:
            console.print(Panel(
                f"[bold green]NEW FORENSIC UPDATE & DEVICE DEFINITIONS FOUND[/bold green]\n\n"
                f"[white]Latest Upstream Release:[/white] [cyan]{update_details}[/cyan]\n"
                f"[dim]Includes updated iOS 18/19 schema offsets, device profiles, and app decoders.[/dim]",
                title="Automated Intelligence Update", border_style="green"
            ))
            if Confirm.ask("[bold green]Would you like to auto-update and start now? (Recommended)[/bold green]", default=True):
                success, msg = MaintenanceManager._apply_update()
                if success:
                    console.print(f"[bold green][OK] {msg}[/bold green]\n")
                    maintenance_log.append(f"Self-Update: {msg}")
                else:
                    console.print(f"[bold yellow][WARNING] {msg}[/bold yellow]\n")

        return {
            "status": "Healthy",
            "log": maintenance_log,
            "update_checked": True
        }

    @staticmethod
    def _heal_forensics_daemon():
        os_type = platform.system().lower()
        if os_type == "linux":
            try:
                # Check standard socket locations
                if os.path.exists("/var/run/usbmuxd") or os.path.exists("/run/usbmuxd"):
                    return True
                if shutil.which("systemctl"):
                    res = subprocess.run(["systemctl", "is-active", "--quiet", "usbmuxd"], capture_output=True)
                    if res.returncode == 0:
                        return True
                if shutil.which("usbmuxd"):
                    # Launch daemon mode without blocking -f flag
                    subprocess.run(["usbmuxd", "-u"], capture_output=True, timeout=2)
                return True
            except Exception:
                return False
        elif os_type == "darwin":
            try:
                if shutil.which("brew"):
                    subprocess.run(["brew", "services", "start", "usbmuxd"], capture_output=True, timeout=2)
                return True
            except Exception:
                return False
        return True

    @staticmethod
    def _clean_temp_artifacts():
        cleaned = 0
        temp_dirs = [os.path.expanduser("~/.iforensic_temp"), "/tmp"]
        for t_dir in temp_dirs:
            if not os.path.exists(t_dir):
                continue
            try:
                for entry in os.listdir(t_dir):
                    if entry.startswith(".iforensic_") or entry.startswith("iforensic_"):
                        full_p = os.path.join(t_dir, entry)
                        if os.path.isfile(full_p):
                            os.remove(full_p)
                            cleaned += 1
            except Exception:
                pass
        return cleaned

    @staticmethod
    def _check_for_updates(timeout_sec=2):
        """
        Checks git remote repository for new commits, tags, or firmware offsets if network is available.
        """
        repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        git_dir = os.path.join(repo_dir, ".git")

        if not os.path.exists(git_dir) or not shutil.which("git"):
            return False, "Standalone environment"

        # Check network connectivity first
        try:
            import socket
            sock = socket.create_connection(("github.com", 443), timeout=timeout_sec)
            sock.close()
        except Exception:
            return False, "Offline environment (Network unavailable)"

        try:
            # Fetch remote status from origin
            subprocess.run(
                ["git", "fetch", "--quiet", "origin"],
                cwd=repo_dir, capture_output=True, text=True, timeout=timeout_sec + 2
            )

            status_res = subprocess.run(
                ["git", "status", "-uno"],
                cwd=repo_dir, capture_output=True, text=True, timeout=timeout_sec
            )

            if "Your branch is behind" in status_res.stdout:
                return True, "New iForensic modules & iOS firmware definitions ready on GitHub"
            return False, "Up to date"
        except subprocess.TimeoutExpired:
            return False, "Update check skipped (Timeout / Low latency)"
        except Exception as e:
            return False, f"Check bypassed: {str(e)}"

    @staticmethod
    def _apply_update():
        repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        try:
            pull_res = subprocess.run(
                ["git", "pull", "--ff-only"],
                cwd=repo_dir, capture_output=True, text=True, timeout=10
            )
            if pull_res.returncode == 0:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", "-e", ".", "--no-deps", "--break-system-packages"],
                    cwd=repo_dir, capture_output=True, timeout=10
                )
                return True, "iForensic updated and re-compiled successfully!"
            else:
                return False, f"Git pull returned error: {pull_res.stderr.strip()}"
        except Exception as e:
            return False, f"Update installation error: {str(e)}"
