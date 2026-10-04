#!/usr/bin/env python3
import os
import sys
import time
import argparse
import subprocess
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Prompt, Confirm
from rich import box

# Core & Parsers
from core.device_detector import DeviceDetector
from core.storage_manager import StorageManager
from core.manifest_resolver import ManifestResolver
from core.timeline import TimelineEngine
from core.hash_verifier import HashVerifier
from core.crypto_engine import CryptoEngine
from core.hardware_imaging import HardwareImaging
from core.maintenance_manager import MaintenanceManager
from parsers.sms_parser import SMSParser
from parsers.calls_parser import CallsParser
from parsers.notes_parser import NotesParser
from parsers.contacts_parser import ContactsParser
from parsers.whatsapp_parser import WhatsAppParser
from parsers.safari_parser import SafariParser
from parsers.photos_parser import PhotosParser
from parsers.data_usage_parser import DataUsageParser
from parsers.financial_parser import FinancialParser
from parsers.recordings_parser import RecordingsParser
from parsers.enterprise_apps_parser import EnterpriseAppsParser
from parsers.universal_apps_parser import UniversalAppEngine
from parsers.keychain_parser import KeychainParser
from exporters.docx_report import DocxReportExporter
from exporters.html_dashboard import HTMLDashboardExporter
from exporters.plain_text_tree_exporter import PlainTextTreeExporter

console = Console()

BANNER = """[bold cyan]
  ██╗███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗
  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝
  ██║█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     
  ██║██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     
  ██║██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗
  ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝
[/bold cyan]
  [bold white]Next-Gen iOS Digital Forensics & Extraction Suite[/bold white]
  [bold green]👨‍💻 Developed by LazZy[/bold green] [dim]| Lead: ANUDITKHATRI2011@GMAIL.COM[/dim]
  [dim]Standard: Enterprise / Court & Disclosure Ready | Multi-Artifact Carving[/dim]
"""

class iForensicCLI:
    def __init__(self, automated_mode=False, password=None):
        self.automated_mode = automated_mode
        self.backup_password = password
        self.active_backup_dir = None
        self.output_storage_dir = None
        self.manifest_resolver = None
        self.decrypted_manifest_path = None
        self.crypto_engine = None
        # Automated Startup Maintenance & Self-Healing
        self.maintenance_result = MaintenanceManager.run_startup_maintenance()
        self.extracted_data = {
            "messages": [],
            "calls": [],
            "notes": [],
            "contacts": [],
            "recordings": {"voice_memos": [], "voicemails": [], "carved_audio_files": [], "total_audio_artifacts": 0},
            "enterprise_apps": {"telegram": [], "signal": [], "teams": [], "protonmail": [], "total_enterprise_records": 0},
            "whatsapp": [],
            "safari": [],
            "photos": [],
            "app_usage": [],
            "financial": [],
            "keychain": {"wifi_networks": [], "web_credentials": [], "app_tokens_and_keys": [], "vpn_and_system": [], "crypto_keys": [], "certificates": [], "all_decrypted_records": [], "total_secrets": 0},
            "timeline": [],
            "custody_manifest": {}
        }

    def handle_decryption_if_needed(self, force_prompt=False):
        """
        Detects if target backup is encrypted, extracts KeyBag parameters, derives master key
        via PBKDF2/scrypt, unwraps Protection Class Keys (RFC 3394), and decrypts Manifest.db.
        """
        if not self.active_backup_dir or not os.path.exists(self.active_backup_dir):
            return None

        crypto = CryptoEngine(self.active_backup_dir)
        if not crypto.is_encrypted:
            return None

        kb_summary = crypto.get_keybag_summary()

        table = Table(title="🔒 Hardware Encrypted iOS Backup & KeyBag Detected", box=box.ROUNDED, border_style="yellow")
        table.add_column("Cryptographic Parameter", style="bold white", width=28)
        table.add_column("KeyBag Telemetry Value", style="bold yellow")

        table.add_row("Encryption Standard", "AES-256-CBC (Hardware Protected)")
        table.add_row("KeyBag UUID", str(kb_summary.get("keybag_uuid")))
        table.add_row("Key Derivation Method", str(kb_summary.get("kdf_method")))
        table.add_row("PBKDF2 Iterations", f"{kb_summary.get('pbkdf2_iterations', 0):,}")
        table.add_row("Protection Classes Detected", f"{kb_summary.get('total_classes_detected', 0)} Classes (Class 1-11)")
        console.print(table)

        if not self.backup_password and not self.automated_mode and not force_prompt:
            decrypt_choice = Confirm.ask("\n[bold green]Would you like to decrypt this encrypted evidence now with the backup password? (Recommended)[/bold green]", default=True)
            if not decrypt_choice:
                console.print("[bold yellow]✔ Decryption deferred. Raw encrypted bitstream and KeyBag parameters safely preserved.[/bold yellow]")
                console.print("[dim]You can unlock this evidence later from Option 10 in the main menu or with 'iforensic -b <path> -p <pass>'.[/dim]\n")
                if self.output_storage_dir:
                    crypto.export_keybag_manifest(os.path.join(self.output_storage_dir, "Cryptographic_KeyBag_Manifest.txt"))
                return None

        pwd = self.backup_password
        max_tries = 3 if not pwd else 1

        for attempt in range(1, max_tries + 1):
            if not pwd:
                pwd = Prompt.ask("[bold cyan]Enter iOS Backup Passphrase (or leave empty to skip)[/bold cyan]", password=True)
                if not pwd:
                    console.print("[bold yellow]Skipping decryption. Only unencrypted artifacts will be processed.[/bold yellow]")
                    if self.output_storage_dir:
                        crypto.export_keybag_manifest(os.path.join(self.output_storage_dir, "Cryptographic_KeyBag_Manifest.txt"))
                    return None

            with console.status("[bold cyan]Deriving cryptographic keys & unwrapping Protection Classes...", spinner="dots"):
                success, msg = crypto.verify_and_unlock(pwd)

            if success:
                console.print(f"[bold green]✔ {msg}[/bold green]")
                stg_dir = self.output_storage_dir or os.path.join(self.active_backup_dir, "decrypted_staging")
                os.makedirs(stg_dir, exist_ok=True)
                dec_manifest = os.path.join(stg_dir, "Manifest_decrypted.db")
                dec_ok, dec_msg = crypto.decrypt_manifest_db(dec_manifest)
                if dec_ok:
                    console.print(f"[bold green]✔ {dec_msg}[/bold green]")
                    self.decrypted_manifest_path = dec_manifest
                    self.crypto_engine = crypto
                    crypto.export_keybag_manifest(os.path.join(stg_dir, "Cryptographic_KeyBag_Manifest.txt"))
                    if self.output_storage_dir:
                        crypto.export_keybag_manifest(os.path.join(self.output_storage_dir, "Cryptographic_KeyBag_Manifest.txt"))
                    return dec_manifest
                else:
                    console.print(f"[bold red]❌ {dec_msg}[/bold red]")
                    return None
            else:
                console.print(f"[bold red]❌ {msg} (Attempt {attempt}/{max_tries})[/bold red]")
                pwd = None

        return None

    def print_banner(self):
        console.clear()
        console.print(BANNER)

    def select_storage_target(self, case_name="evidence"):
        """
        Interactive storage destination selection: Internal Storage vs Auto-detected External USB Storage.
        """
        if self.automated_mode:
            # Auto-mode defaults to internal storage
            default_dir = os.path.expanduser(f"~/Desktop/ios_forensics_cases/iforensic_{case_name}")
            os.makedirs(default_dir, exist_ok=True)
            return default_dir

        self.print_banner()
        console.print(Panel(
            "[bold cyan]STORAGE DESTINATION CONFIGURATION[/bold cyan]\n\n"
            "Where would you like to store the acquired evidence and extracted forensic reports?\n\n"
            "[bold yellow][1][/bold yellow] [bold green](Recommended - Fast NVMe/SSD)[/bold green] [bold white]Internal System Storage[/bold white]\n"
            "    [dim]↳ Target: ~/Desktop/ios_forensics_cases/iforensic_{case_name}[/dim]\n\n"
            "[bold yellow][2][/bold yellow] [bold cyan](Recommended for Evidence Isolation)[/bold cyan] [bold white]External USB Drive / Hard Drive[/bold white]\n"
            "    [dim]↳ Auto-scans attached USB storage media and configures mount partition[/dim]\n\n"
            "[bold yellow][3][/bold yellow] [bold white]Custom Directory Path[/bold white]\n"
            "    [dim]↳ Specify any custom local or network folder[/dim]",
            title="Evidence Destination Target", border_style="cyan"
        ))

        choice = Prompt.ask("[bold cyan]Select storage destination [1-3] (Default: 1 - Recommended)[/bold cyan]", default="1")

        if choice == "2":
            return self._select_external_storage(case_name)
        elif choice == "3":
            custom_dir = Prompt.ask("[bold cyan]Enter custom destination directory[/bold cyan]")
            target = os.path.join(custom_dir, f"iforensic_{case_name}")
            os.makedirs(target, exist_ok=True)
            return target
        else:
            default_dir = os.path.expanduser(f"~/Desktop/ios_forensics_cases/iforensic_{case_name}")
            os.makedirs(default_dir, exist_ok=True)
            return default_dir

    def _select_external_storage(self, case_name="evidence"):
        while True:
            with console.status("[bold cyan]Scanning for attached external USB drives and storage media...", spinner="dots"):
                time.sleep(1.0)
                ext_devices = StorageManager.list_external_storage()

            if not ext_devices:
                console.print(Panel(
                    "[bold red]❌ No External USB Storage Device Detected[/bold red]\n\n"
                    "1. Connect your external USB hard drive or flash drive.\n"
                    "2. Wait 3 seconds for the OS to recognize the USB device.\n"
                    "3. Select [bold cyan][R][/bold cyan] to Retry scan or [bold green][I] (Recommended)[/bold green] to use Internal storage instead.",
                    title="External Drive Not Found", border_style="red"
                ))
                sub_c = Prompt.ask("[bold cyan][R] Retry Scan | [I] (Recommended) Fallback to Internal Storage[/bold cyan]", default="R")
                if sub_c.upper() == "I":
                    default_dir = os.path.expanduser(f"~/Desktop/ios_forensics_cases/iforensic_{case_name}")
                    os.makedirs(default_dir, exist_ok=True)
                    return default_dir
                continue

            table = Table(title="Connected External Storage Devices", box=box.ROUNDED, border_style="green")
            table.add_column("Option", style="bold yellow", width=8)
            table.add_column("Drive Name / Label", style="bold white")
            table.add_column("Path / Partition", style="cyan")
            table.add_column("Filesystem", style="dim")
            table.add_column("Total Size", style="bold cyan", justify="right")
            table.add_column("Free Space", style="bold green", justify="right")
            table.add_column("Recommendation / Status", style="yellow")

            for idx, dev in enumerate(ext_devices, 1):
                m_status = f"[green]✔ (Recommended) Mounted[/green]" if dev.get("is_mounted") else "[yellow]Unmounted (Auto-Mountable)[/yellow]"
                table.add_row(
                    f"[{idx}]",
                    dev.get("label", "External Drive"),
                    dev.get("path", "N/A"),
                    dev.get("fstype", "N/A"),
                    f"{dev.get('size_gb')} GB",
                    f"{dev.get('free_gb')} GB",
                    m_status
                )

            console.print(table)
            console.print("[bold white][R][/bold white] Refresh / Rescan Devices")
            console.print("[bold white][I][/bold white] [green](Recommended Fallback)[/green] Use Internal Storage Instead\n")

            dev_choice = Prompt.ask("[bold cyan]Select external drive option [1-N] (Default: 1 - Recommended)[/bold cyan]", default="1")

            if dev_choice.upper() == "R":
                continue
            elif dev_choice.upper() == "I":
                default_dir = os.path.expanduser(f"~/Desktop/ios_forensics_cases/iforensic_{case_name}")
                os.makedirs(default_dir, exist_ok=True)
                return default_dir
            else:
                try:
                    s_idx = int(dev_choice) - 1
                    if 0 <= s_idx < len(ext_devices):
                        chosen_dev = ext_devices[s_idx]
                        with console.status(f"[bold cyan]Configuring and mounting {chosen_dev.get('label')}...", spinner="dots"):
                            success, mount_dir = StorageManager.mount_device_if_needed(chosen_dev)

                        if success and mount_dir:
                            console.print(f"[bold green]✔ Storage Target Configured at:[/bold green] [cyan]{mount_dir}[/cyan]")
                            target_dir = os.path.join(mount_dir, "iforensic_evidence", f"case_{case_name}")
                            os.makedirs(target_dir, exist_ok=True)
                            time.sleep(1.0)
                            return target_dir
                        else:
                            console.print(f"[bold red]❌ Failed to mount device: {mount_dir}[/bold red]")
                            time.sleep(1.5)
                except ValueError:
                    pass

    def run_1click_auto_fetch(self):
        """
        One-Command Unified Pipeline (Auto-Detect -> Auto-Pair -> Auto-Select Storage -> Full Carve -> Report).
        """
        self.print_banner()
        console.print(Panel(
            "[bold green]⚡ 1-COMMAND COMPLETE AUTONOMOUS FORENSIC PIPELINE[/bold green]\n"
            "[dim]Auto-detecting hardware, lockdown pairing, evidence resolution, and full artifact carving...[/dim]",
            border_style="green"
        ))

        # 1. Detect USB Hardware
        with console.status("[bold cyan]Step 1/4: Checking connected USB iOS hardware...", spinner="dots"):
            time.sleep(0.8)
            udids = DeviceDetector.detect_connected_devices()

        if udids:
            target_udid = udids[0]
            console.print(f"[bold green]✔ iOS Device Connected via USB:[/bold green] [cyan]{target_udid}[/cyan]")
            
            # Check pairing
            is_paired, _ = DeviceDetector.validate_pairing(target_udid)
            if not is_paired:
                console.print("[bold yellow]⚠️ Pairing with connected device... Unlock iPhone & tap 'Trust'[/bold yellow]")
                DeviceDetector.pair_device(target_udid)

            dev_info = DeviceDetector.get_device_info(target_udid)
            case_id = (dev_info.get("device_name", "iphone") + "_" + target_udid[:8]) if dev_info else target_udid[:8]
            dest_dir = self.select_storage_target(case_name=case_id)
            self.output_storage_dir = dest_dir
            self.run_live_acquisition(target_udid, dev_info.get("device_name") if dev_info else "iPhone", dest_dir)
            return

        # 2. If no live USB, auto-search for local evidence backups
        with console.status("[bold cyan]Step 1/4: No live USB device. Scanning for local evidence backups...", spinner="dots"):
            time.sleep(0.8)
            candidates = [
                "/home/lazzy/iphone-test/backup-full/00008110-00184DC63CD3801E",
                "/home/lazzy/Desktop/ios_forensics_cases/00008110-00184DC63CD3801E_20260930_204604",
                "/home/lazzy/iphone-test/backup-full",
                os.path.expanduser("~/Desktop/ios_forensics_cases")
            ]
            found = []
            for c in candidates:
                if os.path.exists(c):
                    if os.path.exists(os.path.join(c, "Manifest.db")) or os.path.exists(os.path.join(c, "Snapshot")) or os.path.exists(os.path.join(c, "Info.plist")):
                        if c not in found:
                            found.append(c)
                    else:
                        try:
                            for entry in os.listdir(c):
                                full = os.path.join(c, entry)
                                if os.path.isdir(full) and (os.path.exists(os.path.join(full, "Manifest.db")) or os.path.exists(os.path.join(full, "Snapshot")) or os.path.exists(os.path.join(full, "Info.plist"))):
                                    if full not in found:
                                        found.append(full)
                        except Exception:
                            pass

        if found:
            selected_backup = found[0]
            console.print(f"[bold green]✔ Auto-Discovered Case Evidence:[/bold green] [cyan]{selected_backup}[/cyan]")
            self.active_backup_dir = selected_backup
            self.output_storage_dir = os.path.join(selected_backup, "forensic_reports")
            self.run_full_fetch()
        else:
            console.print("[bold red]❌ No connected iOS USB device and no local backup folders found.[/bold red]")
            console.print("[dim]Connect your device via USB or provide a backup folder path.[/dim]")
            Prompt.ask("\n[bold cyan]Press Enter to return to main menu[/bold cyan]")

    def menu_device_diagnostics(self):
        """
        Step 1: Check hardware connection, lockdown pairing state, and device telemetry.
        """
        self.print_banner()
        console.print(Panel("[bold yellow]STEP 1: USB HARDWARE & PAIRING DIAGNOSTICS (RECOMMENDED FIRST STEP)[/bold yellow]", border_style="yellow"))

        env_status = DeviceDetector.check_environment()
        missing_tools = [k for k, v in env_status.items() if not v]
        if missing_tools:
            console.print(f"[bold red][!] Warning: Missing system utilities: {', '.join(missing_tools)}[/bold red]")
            console.print(f"[dim]{DeviceDetector.get_os_install_guide()}[/dim]\n")

        with console.status("[bold cyan]Scanning USB bus for connected iOS devices via usbmuxd...", spinner="dots"):
            time.sleep(1.2)
            udids = DeviceDetector.detect_connected_devices()

        if not udids:
            console.print(Panel(
                "[bold red]❌ No iOS Device Detected on USB Bus[/bold red]\n\n"
                "[white]Troubleshooting Checklist:[/white]\n"
                "1. Connect the iPhone using an authentic Apple USB-C or Lightning cable.\n"
                "2. Unlock the iPhone screen with your passcode.\n"
                "3. Ensure the usbmuxd service is running ([cyan]sudo systemctl restart usbmuxd[/cyan]).\n"
                "4. If prompted on iPhone, tap [bold green]'Trust This Computer'[/bold green] and enter passcode.",
                title="Hardware Detection Failed", border_style="red"
            ))
            Prompt.ask("\n[bold cyan]Press Enter to return to main menu[/bold cyan]")
            return

        target_udid = udids[0]
        console.print(f"[bold green]✔ iOS Device Detected on USB Bus![/bold green] (UDID: [cyan]{target_udid}[/cyan])\n")

        with console.status("[bold cyan]Querying lockdown cryptographic pairing status...", spinner="dots"):
            time.sleep(0.8)
            is_paired, pair_msg = DeviceDetector.validate_pairing(target_udid)

        if not is_paired:
            console.print(Panel(
                f"[bold yellow]⚠️ Device Connected But NOT Trusted / Paired[/bold yellow]\n\n"
                f"[white]Status:[/white] {pair_msg}\n\n"
                "[bold cyan]Action Required:[/bold cyan]\n"
                "1. Look at your iPhone screen right now.\n"
                "2. Tap [bold green]'Trust'[/bold green] on the 'Trust This Computer?' dialog.\n"
                "3. Enter your device passcode.",
                title="Pairing Verification Required", border_style="yellow"
            ))
            if Confirm.ask("[bold green]Attempt pairing handshake now? (Recommended)[/bold green]", default=True):
                paired_ok, p_res = DeviceDetector.pair_device(target_udid)
                if paired_ok:
                    console.print(f"[bold green]✔ {p_res}[/bold green]")
                else:
                    console.print(f"[bold red]❌ {p_res}[/bold red]")
                    Prompt.ask("\n[bold cyan]Press Enter to return[/bold cyan]")
                    return

        with console.status("[bold cyan]Extracting device hardware and OS telemetry...", spinner="dots"):
            time.sleep(1.0)
            dev_info = DeviceDetector.get_device_info(target_udid)

        if dev_info:
            table = Table(title="Connected Device Profile", box=box.ROUNDED, border_style="cyan")
            table.add_column("Property", style="bold white", width=24)
            table.add_column("Telemetry Value", style="cyan")

            table.add_row("Device Name", dev_info.get("device_name"))
            table.add_row("Product Model", dev_info.get("product_type"))
            table.add_row("iOS Version", f"{dev_info.get('product_version')} (Build {dev_info.get('build_version')})")
            table.add_row("Serial Number", dev_info.get("serial_number"))
            table.add_row("UDID", dev_info.get("udid"))
            table.add_row("Battery Level", dev_info.get("battery_level"))
            table.add_row("Wi-Fi MAC Address", dev_info.get("wi_fi_address"))
            table.add_row("Baseband Firmware", dev_info.get("baseband_version"))
            table.add_row("Time Zone", dev_info.get("time_zone"))

            # Physical Imaging / Checkm8 Compatibility Analysis
            c8_profile = HardwareImaging.evaluate_checkm8_compatibility(dev_info)
            c8_status = "[bold green]✔ Eligible (A7-A11 BootROM DFU)[/bold green]" if c8_profile.get("eligible") else "[dim]Standard Logical Lockdownd (A12+ Secure Enclave)[/dim]"
            table.add_row("Physical Imaging Profile", c8_status)
            table.add_row("Exploitation Method", c8_profile.get("physical_acquisition_method"))
            console.print(table)

            if Confirm.ask("\n[bold green]Would you like to configure storage and trigger full live acquisition now? (Recommended)[/bold green]", default=True):
                dest_storage = self.select_storage_target(case_name=dev_info.get("udid", "device")[:8])
                self.output_storage_dir = dest_storage
                self.run_live_acquisition(target_udid, dev_info.get("device_name"), dest_storage)
        else:
            console.print("[bold red]Failed to retrieve hardware profile. Verify device unlock state.[/bold red]")

        Prompt.ask("\n[bold cyan]Press Enter to return to main menu[/bold cyan]")

    def display_preflight_device_checklist(self):
        """
        Pre-flight anti-restricted mode and screen preservation checklist.
        Specifically handles 2.1 worst case: auto-brightness off, auto-lock never, battery headroom.
        """
        console.print(Panel(
            "[bold yellow]⚠️ PRE-FLIGHT DEVICE PREPARATION CHECKLIST (ANTI-RESTRICTED MODE)[/bold yellow]\n\n"
            "[bold white]To ensure uninterrupted extraction and prevent iOS USB Restricted Mode or Thermal Throttling:[/bold white]\n\n"
            " 1. [bold cyan]Auto-Brightness:[/bold cyan] Go to [bold white]Settings > Accessibility > Display & Text Size[/bold white] → Turn [bold red]OFF Auto-Brightness[/bold red] and set brightness to minimum (prevents thermal throttling & rapid battery drain).\n"
            " 2. [bold cyan]Auto-Lock / Screen Timeout:[/bold cyan] Go to [bold white]Settings > Display & Brightness[/bold white] → Set [bold green]Auto-Lock to 'Never'[/bold green] (prevents USB Restricted Mode from disconnecting the interface).\n"
            " 3. [bold cyan]Lockdown Pairing:[/bold cyan] Keep device screen unlocked with passcode entered and confirm [bold green]'Trust This Computer'[/bold green].\n"
            " 4. [bold cyan]Battery Level:[/bold cyan] Ensure battery is at least 50% or connected to continuous power.\n",
            title="Field Protocol: iOS Device Setup",
            border_style="yellow"
        ))
        return Confirm.ask("[bold green]Have you applied these pre-flight settings on the iPhone? (Recommended)[/bold green]", default=True)

    def run_live_acquisition(self, udid, device_name, destination_dir):
        os.makedirs(destination_dir, exist_ok=True)

        # 1. Pre-flight Device Settings Checklist (Auto-Brightness Off, Auto-Lock Never)
        self.display_preflight_device_checklist()

        # 2. Pre-flight Host Storage Space Check
        try:
            total, used, free = shutil.disk_usage(destination_dir)
            free_gb = round(free / (1024**3), 2)
            if free_gb < 15.0:
                console.print(Panel(
                    f"[bold red]⚠️ LOW DISK SPACE WARNING[/bold red]\n\n"
                    f"Destination drive has only [bold yellow]{free_gb} GB[/bold yellow] free.\n"
                    f"A full iPhone backup typically requires 20–128 GB. Acquisition may run out of disk space.",
                    border_style="red"
                ))
                if not Confirm.ask("[bold yellow]Do you still wish to proceed with this storage destination?[/bold yellow]", default=False):
                    destination_dir = self.select_storage_target(case_name=udid[:8])
                    self.output_storage_dir = destination_dir
        except Exception:
            pass

        console.print(Panel(
            f"[bold green]Starting Live Forensic Acquisition[/bold green]\n"
            f"[white]Target Destination:[/white] [cyan]{destination_dir}[/cyan]\n"
            f"[dim]Executing idevicebackup2 backup --full protocol with auto-resume...[/dim]",
            border_style="green"
        ))

        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            cmd = ["idevicebackup2", "-u", udid, "backup", "--full", destination_dir]
            try:
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold cyan]{task.description}"),
                    BarColumn(bar_width=40, complete_style="green", finished_style="bold green"),
                    TimeElapsedColumn(),
                    console=console
                ) as progress:
                    task = progress.add_task(f"Acquiring raw device filesystem (Attempt {attempt}/{max_attempts})...", total=None)
                    while True:
                        line = p.stdout.readline()
                        if not line and p.poll() is not None:
                            break
                        if line:
                            clean_l = line.strip()
                            if "Receiving files" in clean_l or "Writing files" in clean_l:
                                progress.update(task, description=f"[cyan]{clean_l[:50]}")

                p.wait()
                if p.returncode == 0:
                    console.print(f"\n[bold green]✔ USB Acquisition Completed Successfully![/bold green]")
                    backup_path = os.path.join(destination_dir, udid)
                    self.active_backup_dir = backup_path

                    crypto_check = CryptoEngine(backup_path)
                    if crypto_check.is_encrypted:
                        kb_summary = crypto_check.get_keybag_summary()
                        console.print(Panel(
                            f"[bold green]✔ Cryptographic KeyBag Carved Successfully During Acquisition[/bold green]\n\n"
                            f"[white]KeyBag UUID:[/white] [cyan]{kb_summary.get('keybag_uuid')}[/cyan]\n"
                            f"[white]Key Derivation:[/white] [cyan]{kb_summary.get('kdf_method')}[/cyan]\n"
                            f"[white]Protection Classes:[/white] [yellow]{kb_summary.get('total_classes_detected')} Classes (Class 1-11)[/yellow]\n"
                            f"[dim]The backup filesystem and embedded KeyBag are fully preserved on disk.[/dim]",
                            title="Cryptographic Hardware Acquisition", border_style="green"
                        ))

                    self.run_full_fetch()
                    return
                else:
                    console.print(f"\n[bold yellow]⚠️ Acquisition attempt {attempt} returned code {p.returncode}. Healing usbmuxd socket...[/bold yellow]")
                    DeviceDetector.self_heal_usbmuxd()
                    time.sleep(2.0)
            except Exception as e:
                console.print(f"[bold red]Acquisition error: {str(e)}[/bold red]")
                DeviceDetector.self_heal_usbmuxd()
                time.sleep(2.0)

        console.print("[bold red]❌ Live acquisition failed after multiple attempts. Please re-verify USB connection and device unlock state.[/bold red]")

    def prompt_quick_selective_targets(self):
        self.print_banner()
        console.print(Panel(
            "[bold cyan]⚡ QUICK SELECTIVE FETCH — TARGET & ARTIFACT CONFIGURATION[/bold cyan]\n\n"
            "[bold white]Choose an extraction preset or pick custom modules to extract in seconds:[/bold white]\n\n"
            "[bold yellow][1][/bold yellow] [bold green](Recommended Preset - Tactical Intelligence)[/bold green] Comms + Notes + Passwords + Financial Ledgers\n"
            "    [dim]↳ Extracts SMS/iMessage, Calls, Contacts, Notes, Keychain/Keys, WhatsApp, Telegram/Teams, Financial (~2-4s)[/dim]\n\n"
            "[bold yellow][2][/bold yellow] [bold cyan](Preset - All Messaging & Social Comms)[/bold cyan] SMS + Calls + Contacts + WhatsApp + Telegram + Signal + Teams\n"
            "    [dim]↳ Focused solely on communication logs, chat history, and contact graph[/dim]\n\n"
            "[bold yellow][3][/bold yellow] [bold yellow](Preset - Financial & Credentials Only)[/bold yellow] Bank OTPs + Transactions + Notes Passwords + Decrypted Keychain & Keys\n"
            "    [dim]↳ Scans for financial movements, banking OTPs, wallets, Wi-Fi passwords, and decrypted credentials[/dim]\n\n"
            "[bold yellow][4][/bold yellow] [bold magenta](Preset - Audio & Media Metadata)[/bold magenta] Voice Memos + Voicemails + Audio Tracks + Photos GPS\n"
            "    [dim]↳ Carves recordings, voicemails (transcriptions), and EXIF geotags[/dim]\n\n"
            "[bold yellow][5][/bold yellow] [bold white]Custom Selective Target Checkboxes (Pick any combination)[/bold white]\n"
            "    [dim]↳ Interactively select specific artifacts (e.g. 1,3,5,12)[/dim]\n\n"
            "[bold yellow][0][/bold yellow] Return to Main Menu",
            title="Quick Fetch Configuration", border_style="cyan"
        ))

        c = Prompt.ask("[bold cyan]Select an option [0-5] (Default: 1 - Recommended Tactical Preset)[/bold cyan]", default="1")
        if c == "0":
            return None
        elif c == "1":
            return {"messages", "calls", "contacts", "notes", "whatsapp", "enterprise", "financial", "keychain"}
        elif c == "2":
            return {"messages", "calls", "contacts", "whatsapp", "enterprise"}
        elif c == "3":
            return {"notes", "financial", "messages", "keychain"}
        elif c == "4":
            return {"recordings", "photos", "contacts"}
        elif c == "5":
            return self._prompt_custom_checkboxes()
        else:
            return {"messages", "calls", "contacts", "notes", "whatsapp", "enterprise", "financial", "keychain"}

    def _prompt_custom_checkboxes(self):
        console.print(Panel(
            "[bold cyan]SELECT SPECIFIC MODULES TO EXTRACT[/bold cyan]\n\n"
            " [1] SMS & iMessage (iOS 16/17/18+ TypedStreams)\n"
            " [2] Call History & Voice Telemetry\n"
            " [3] Contacts & Truecaller Directory\n"
            " [4] Apple Notes & Stored Passwords (Gzip/Protobufs)\n"
            " [5] WhatsApp Chats & Groups\n"
            " [6] Enterprise Apps (Telegram, Signal, Teams, ProtonMail)\n"
            " [7] Financial Ledgers & Bank OTPs\n"
            " [8] Voice Memos & Voicemails (with Transcriptions)\n"
            " [9] Safari Web History & Bookmarks\n"
            "[10] Photos Metadata & GPS Geotags\n"
            "[11] Unlisted Third-Party Database Heuristic Carver\n"
            "[12] Decrypted Keychain & Cryptographic Keys (Wi-Fi, Safari Logins, Database Keys)\n\n"
            "[dim]Enter comma-separated numbers (e.g. 1,3,5,12 or 1-4,7,12) or 'all'[/dim]",
            border_style="yellow"
        ))
        sel = Prompt.ask("[bold cyan]Enter module numbers to extract[/bold cyan]", default="1,2,3,4,5,6,7,12")
        if sel.lower() == "all":
            return {"messages", "calls", "contacts", "notes", "whatsapp", "enterprise", "financial", "recordings", "safari", "photos", "unlisted", "keychain"}

        mapping = {
            "1": "messages",
            "2": "calls",
            "3": "contacts",
            "4": "notes",
            "5": "whatsapp",
            "6": "enterprise",
            "7": "financial",
            "8": "recordings",
            "9": "safari",
            "10": "photos",
            "11": "unlisted",
            "12": "keychain"
        }

        chosen = set()
        for token in sel.replace(" ", "").split(","):
            if "-" in token:
                try:
                    start_s, end_s = token.split("-", 1)
                    for n in range(int(start_s), int(end_s) + 1):
                        k = str(n)
                        if k in mapping:
                            chosen.add(mapping[k])
                except ValueError:
                    pass
            elif token in mapping:
                chosen.add(mapping[token])

        return chosen or {"messages", "calls", "contacts", "notes", "whatsapp", "enterprise", "financial", "keychain"}

    def load_existing_backup(self, target_fetch_mode="full"):
        self.print_banner()
        title_str = "LOAD EVIDENCE FOR QUICK SELECTIVE FETCH" if target_fetch_mode == "selective" else "LOAD EVIDENCE FOR FULL DEEP FORENSIC ACQUISITION"
        console.print(Panel(f"[bold cyan]{title_str}[/bold cyan]", border_style="cyan"))

        candidates = [
            "/home/lazzy/iphone-test/backup-full/00008110-00184DC63CD3801E",
            "/home/lazzy/Desktop/ios_forensics_cases/00008110-00184DC63CD3801E_20260930_204604",
            "/home/lazzy/iphone-test/backup-full",
            os.path.expanduser("~/Desktop/ios_forensics_cases"),
            os.path.expanduser("~/.local/share/libimobiledevice/backup")
        ]

        found = []
        for c in candidates:
            if os.path.exists(c):
                if os.path.exists(os.path.join(c, "Manifest.db")) or os.path.exists(os.path.join(c, "Snapshot")) or os.path.exists(os.path.join(c, "Info.plist")):
                    if c not in found:
                        found.append(c)
                else:
                    try:
                        for entry in os.listdir(c):
                            full = os.path.join(c, entry)
                            if os.path.isdir(full) and (os.path.exists(os.path.join(full, "Manifest.db")) or os.path.exists(os.path.join(full, "Snapshot")) or os.path.exists(os.path.join(full, "Info.plist"))):
                                if full not in found:
                                    found.append(full)
                    except Exception:
                        pass

        table = Table(title="Discovered Local Evidence Backups", box=box.ROUNDED, border_style="cyan")
        table.add_column("Option", style="bold yellow", width=8)
        table.add_column("Backup Path", style="cyan")
        table.add_column("Recommendation / Status", style="green", width=24)

        for idx, f in enumerate(found, 1):
            rec_tag = "[bold green]✔ (Recommended)[/bold green]" if idx == 1 else "[green]✔ Evidence Ready[/green]"
            table.add_row(f"[{idx}]", f, rec_tag)

        console.print(table)
        console.print("[bold white][C][/bold white] Enter Custom Path")
        console.print("[bold white][0][/bold white] Back to Main Menu\n")

        choice = Prompt.ask("[bold cyan]Select an option [1-N] (Default: 1 - Recommended)[/bold cyan]", default="1")
        if choice == "0":
            return
        elif choice.lower() == "c":
            custom_path = Prompt.ask("[bold cyan]Enter full path to iOS backup directory[/bold cyan]")
            if os.path.exists(custom_path):
                self.active_backup_dir = custom_path
                if target_fetch_mode == "selective":
                    self.run_selective_fetch()
                else:
                    self.run_full_fetch()
            else:
                console.print("[bold red]Invalid backup path or directory not found![/bold red]")
                Prompt.ask("\n[bold cyan]Press Enter to continue[/bold cyan]")
        else:
            try:
                selected_idx = int(choice) - 1
                if 0 <= selected_idx < len(found):
                    self.active_backup_dir = found[selected_idx]
                    if target_fetch_mode == "selective":
                        self.run_selective_fetch()
                    else:
                        self.run_full_fetch()
            except ValueError:
                pass

    def run_selective_fetch(self, selected_targets=None):
        if not self.active_backup_dir or not os.path.exists(self.active_backup_dir):
            console.print("[bold red]No valid backup folder selected![/bold red]")
            self.load_existing_backup(target_fetch_mode="selective")
            return

        if selected_targets is None:
            selected_targets = self.prompt_quick_selective_targets()
            if not selected_targets:
                return

        if not self.output_storage_dir:
            case_id = os.path.basename(self.active_backup_dir)
            self.output_storage_dir = os.path.join(self.active_backup_dir, "quick_forensic_reports")

        os.makedirs(self.output_storage_dir, exist_ok=True)

        self.print_banner()
        target_names = [t.upper() for t in sorted(selected_targets)]
        console.print(Panel(
            f"[bold green]⚡ INITIATING QUICK SELECTIVE FORENSIC FETCH[/bold green]\n"
            f"[white]Active Modules:[/white] [bold yellow]{', '.join(target_names)}[/bold yellow]\n"
            f"[white]Source Evidence:[/white] [cyan]{self.active_backup_dir}[/cyan]\n"
            f"[white]Reports Destination:[/white] [yellow]{self.output_storage_dir}[/yellow]",
            border_style="green"
        ))

        # Reset extracted data
        self.extracted_data = {
            "messages": [],
            "calls": [],
            "notes": [],
            "contacts": [],
            "recordings": {"voice_memos": [], "voicemails": [], "carved_audio_files": [], "total_audio_artifacts": 0},
            "enterprise_apps": {"telegram": [], "signal": [], "teams": [], "protonmail": [], "total_enterprise_records": 0},
            "whatsapp": [],
            "safari": [],
            "photos": [],
            "app_usage": [],
            "financial": [],
            "timeline": [],
            "custody_manifest": {}
        }

        specific_files = []
        for mf in ["Manifest.db", "Info.plist", "Manifest.plist", "Status.plist"]:
            mp = os.path.join(self.active_backup_dir, mf)
            if os.path.exists(mp):
                specific_files.append(mp)

        # Check and handle encrypted backup decryption
        dec_manifest = self.handle_decryption_if_needed()
        if dec_manifest and dec_manifest not in specific_files:
            specific_files.append(dec_manifest)

        with Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=45, complete_style="green", finished_style="bold green"),
            TextColumn("[bold white]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            total_task = progress.add_task("Initializing selective triage engine...", total=100)

            # Step 1: Initialize Manifest Resolver (Fast mode - no deep disk walk)
            progress.update(total_task, description="[bold cyan]Resolving database pointers & manifest mapping...", completed=10)
            self.manifest_resolver = ManifestResolver(self.active_backup_dir, deep_fingerprint=False, decrypted_manifest_path=dec_manifest, crypto_engine=self.crypto_engine)

            contacts_parser = None
            if "contacts" in selected_targets or "calls" in selected_targets or "recordings" in selected_targets:
                ab_path = self.manifest_resolver.find_file(filename="AddressBook.sqlitedb")
                tc_path = self.manifest_resolver.find_file(filename="Truecaller.sqlite")
                if ab_path: specific_files.append(ab_path)
                if tc_path: specific_files.append(tc_path)
                contacts_parser = ContactsParser(ab_path, truecaller_path=tc_path)
                if "contacts" in selected_targets:
                    self.extracted_data["contacts"] = contacts_parser.parse()
            progress.update(total_task, completed=25)

            if "messages" in selected_targets:
                progress.update(total_task, description="[bold cyan]Decoding SMS / iMessage TypedStream records...", completed=35)
                sms_path = self.manifest_resolver.find_file(filename="sms.db")
                if sms_path: specific_files.append(sms_path)
                sms_parser = SMSParser(sms_path)
                self.extracted_data["messages"] = sms_parser.parse()
            progress.update(total_task, completed=45)

            if "calls" in selected_targets:
                progress.update(total_task, description="[bold cyan]Parsing CallHistory records & voice telemetry...", completed=50)
                calls_path = self.manifest_resolver.find_file(filename="CallHistory.storedata")
                if calls_path: specific_files.append(calls_path)
                calls_parser = CallsParser(calls_path)
                raw_calls = calls_parser.parse()
                if contacts_parser:
                    for c in raw_calls:
                        if c.get("contact_name") == "Unknown" and c.get("number"):
                            c["contact_name"] = contacts_parser.resolve_number(c["number"])
                self.extracted_data["calls"] = raw_calls
            progress.update(total_task, completed=55)

            if "notes" in selected_targets:
                progress.update(total_task, description="[bold cyan]Decompressing Apple Notes & Passwords...", completed=60)
                notes_path = self.manifest_resolver.find_file(filename="NoteStore.sqlite")
                if notes_path: specific_files.append(notes_path)
                notes_parser = NotesParser(notes_path)
                self.extracted_data["notes"] = notes_parser.parse()
            progress.update(total_task, completed=65)

            if "whatsapp" in selected_targets:
                progress.update(total_task, description="[bold cyan]Decoding WhatsApp chats & groups...", completed=70)
                wa_path = self.manifest_resolver.find_file(filename="ChatStorage.sqlite")
                if wa_path: specific_files.append(wa_path)
                wa_parser = WhatsAppParser(wa_path)
                self.extracted_data["whatsapp"] = wa_parser.parse()
            progress.update(total_task, completed=75)

            if "enterprise" in selected_targets:
                progress.update(total_task, description="[bold cyan]Carving Telegram, Signal, Teams & ProtonMail...", completed=80)
                ent_parser = EnterpriseAppsParser(self.manifest_resolver)
                self.extracted_data["enterprise_apps"] = ent_parser.parse()
            progress.update(total_task, completed=85)

            if "keychain" in selected_targets or "financial" in selected_targets:
                progress.update(total_task, description="[bold cyan]Decrypting Keychain & Carving Cryptographic Keys...", completed=86)
                kc_path = self.manifest_resolver.find_file(filename="keychain-backup.plist") or self.manifest_resolver.find_file(filename="Keychain.plist")
                if kc_path:
                    specific_files.append(kc_path)
                    kc_parser = KeychainParser(kc_path, crypto_engine=self.crypto_engine)
                    self.extracted_data["keychain"] = kc_parser.parse()
                    kc_json_path = os.path.join(self.output_storage_dir, "Keychain_Decrypted_Secrets.json")
                    kc_parser.export_keychain_json(kc_json_path)

            if "recordings" in selected_targets:
                progress.update(total_task, description="[bold cyan]Carving Voice Memos & Voicemails...", completed=88)
                rec_parser = RecordingsParser(manifest_resolver=self.manifest_resolver, contacts_parser=contacts_parser)
                self.extracted_data["recordings"] = rec_parser.parse()

            if "safari" in selected_targets:
                safari_path = self.manifest_resolver.find_file(filename="SafariHistory.db")
                if safari_path: specific_files.append(safari_path)
                safari_parser = SafariParser(safari_path)
                self.extracted_data["safari"] = safari_parser.parse()

            if "photos" in selected_targets:
                photos_path = self.manifest_resolver.find_file(filename="Photos.sqlite")
                if photos_path: specific_files.append(photos_path)
                photos_parser = PhotosParser(photos_path)
                self.extracted_data["photos"] = photos_parser.parse()

            if "unlisted" in selected_targets:
                univ_engine = UniversalAppEngine(self.manifest_resolver)
                res_u = univ_engine.parse()
                self.extracted_data["unlisted_apps"] = res_u

            if "financial" in selected_targets or "messages" in selected_targets or "notes" in selected_targets:
                fin_parser = FinancialParser(messages=self.extracted_data["messages"], notes=self.extracted_data["notes"])
                self.extracted_data["financial"] = fin_parser.parse()

            # Hash only parsed specific files for ultra-fast Chain of Custody (<0.1s)
            progress.update(total_task, description="[bold cyan]Computing NIST CFTT Hashes for Carved Databases...", completed=92)
            custody = HashVerifier.generate_chain_of_custody(
                evidence_dir=self.active_backup_dir,
                output_dir=self.output_storage_dir,
                case_id=os.path.basename(self.active_backup_dir)[:16],
                specific_files=specific_files
            )
            self.extracted_data["custody_manifest"] = custody

            # Build timeline
            timeline_engine = TimelineEngine()
            timeline_engine.ingest_sms(self.extracted_data["messages"])
            timeline_engine.ingest_calls(self.extracted_data["calls"])
            timeline_engine.ingest_notes(self.extracted_data["notes"])
            timeline_engine.ingest_safari(self.extracted_data["safari"])
            self.extracted_data["timeline"] = timeline_engine.build_timeline()

            # Generate Reports
            progress.update(total_task, description="[bold cyan]Generating DOCX & HTML Intelligence Reports...", completed=96)
            meta = self.manifest_resolver.get_summary()

            docx_exp = DocxReportExporter(
                metadata=meta,
                messages=self.extracted_data["messages"],
                calls=self.extracted_data["calls"],
                notes=self.extracted_data["notes"],
                contacts=self.extracted_data["contacts"],
                financial=self.extracted_data["financial"],
                app_usage=self.extracted_data["app_usage"],
                recordings=self.extracted_data["recordings"],
                enterprise_apps=self.extracted_data["enterprise_apps"],
                custody_manifest=self.extracted_data["custody_manifest"],
                keychain=self.extracted_data["keychain"]
            )
            docx_path = os.path.join(self.output_storage_dir, f"iOS_Forensic_Intelligence_Report_{meta.get('udid', 'Case')[:16]}.docx")
            docx_exp.generate(docx_path)

            html_exp = HTMLDashboardExporter(
                metadata=meta,
                messages=self.extracted_data["messages"],
                calls=self.extracted_data["calls"],
                notes=self.extracted_data["notes"],
                contacts=self.extracted_data["contacts"],
                financial=self.extracted_data["financial"],
                app_usage=self.extracted_data["app_usage"],
                recordings=self.extracted_data["recordings"],
                enterprise_apps=self.extracted_data["enterprise_apps"],
                custody_manifest=self.extracted_data["custody_manifest"],
                keychain=self.extracted_data["keychain"]
            )
            html_path = os.path.join(self.output_storage_dir, "Interactive_Forensic_Dashboard.html")
            html_exp.generate(html_path)

            # Export structured plain-text & decrypted folder trees
            progress.update(total_task, description="[bold cyan]Exporting Plain-Text & Categorized Folder Tree...", completed=98)
            plain_exp = PlainTextTreeExporter(
                output_base_dir=self.output_storage_dir,
                extracted_data=self.extracted_data,
                metadata=meta,
                manifest_resolver=self.manifest_resolver
            )
            plain_exp.export_all()

            progress.update(total_task, completed=100, description="[bold green]✔ QUICK SELECTIVE FETCH COMPLETED SUCCESSFULLY!")

        self.display_fetch_summary(docx_path, html_path)

    def run_full_fetch(self):
        if not self.active_backup_dir or not os.path.exists(self.active_backup_dir):
            console.print("[bold red]No valid backup folder selected![/bold red]")
            return

        if not self.output_storage_dir:
            case_id = os.path.basename(self.active_backup_dir)
            if Confirm.ask("\n[bold green]Would you like to select an External USB Drive for saving the forensic reports & exports? (Default: No - Recommended Internal)[/bold green]", default=False):
                self.output_storage_dir = self.select_storage_target(case_name=case_id[:12])
            else:
                self.output_storage_dir = os.path.join(self.active_backup_dir, "forensic_reports")

        os.makedirs(self.output_storage_dir, exist_ok=True)

        self.print_banner()
        console.print(Panel(
            f"[bold green]INITIATING FULL FORENSIC EXTRACTION & DECODING (RECOMMENDED COMPLETE FETCH)[/bold green]\n"
            f"[white]Source Evidence:[/white] [cyan]{self.active_backup_dir}[/cyan]\n"
            f"[white]Reports Destination:[/white] [yellow]{self.output_storage_dir}[/yellow]",
            border_style="green"
        ))

        # Check and handle encrypted backup decryption
        dec_manifest = self.handle_decryption_if_needed()

        with Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=45, complete_style="green", finished_style="bold green"),
            TextColumn("[bold white]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            total_task = progress.add_task("Initializing enterprise forensic decoding engine...", total=100)

            # Stage 1: NIST CFTT Hash Verification & Chain of Custody (0 -> 8%)
            progress.update(total_task, description="[bold cyan]Stage 1/12: Computing NIST CFTT SHA-256/MD5 Hashes & Chain of Custody Manifest...", completed=4)
            custody = HashVerifier.generate_chain_of_custody(
                evidence_dir=self.active_backup_dir,
                output_dir=self.output_storage_dir,
                case_id=os.path.basename(self.active_backup_dir)[:16]
            )
            self.extracted_data["custody_manifest"] = custody
            progress.update(total_task, completed=8)

            # Stage 2: Hardware Write-Blocker Validation & Manifest Resolver (8 -> 16%)
            progress.update(total_task, description="[bold cyan]Stage 2/12: Validating Hardware Write-Blocker Status & SQLite Fingerprinting...", completed=12)
            wb_status = HardwareImaging.check_write_blocker_status(self.active_backup_dir)
            self.manifest_resolver = ManifestResolver(self.active_backup_dir, deep_fingerprint=True, decrypted_manifest_path=dec_manifest, crypto_engine=self.crypto_engine)
            if self.manifest_resolver.device_metadata:
                self.manifest_resolver.device_metadata["write_blocker_detected"] = wb_status.get("write_blocker_detected")
            progress.update(total_task, completed=16)

            # Stage 3: Encrypted Backup KeyBag & Keychain Cryptographic Extraction (16 -> 24%)
            progress.update(total_task, description="[bold cyan]Stage 3/12: Unwrapping KeyBag & Decrypting iOS Keychain (Wi-Fi, Safari, Database Keys)...", completed=20)
            kc_path = self.manifest_resolver.find_file(filename="keychain-backup.plist") or self.manifest_resolver.find_file(filename="Keychain.plist")
            if kc_path:
                kc_parser = KeychainParser(kc_path, crypto_engine=self.crypto_engine)
                self.extracted_data["keychain"] = kc_parser.parse()
                kc_json_path = os.path.join(self.output_storage_dir, "Keychain_Decrypted_Secrets.json")
                kc_parser.export_keychain_json(kc_json_path)
            if dec_manifest:
                progress.update(total_task, description="[bold green]✔ Stage 3/12: AES-256 KeyBag Unwrapped & Keychain Decrypted", completed=24)
            else:
                progress.update(total_task, completed=24)

            # Stage 4: Contacts & Truecaller Cache (24 -> 34%)
            progress.update(total_task, description="[bold cyan]Stage 4/12: Parsing AddressBook.sqlitedb & cross-referencing Truecaller...", completed=28)
            ab_path = self.manifest_resolver.find_file(filename="AddressBook.sqlitedb")
            tc_path = self.manifest_resolver.find_file(filename="Truecaller.sqlite")
            contacts_parser = ContactsParser(ab_path, truecaller_path=tc_path)
            self.extracted_data["contacts"] = contacts_parser.parse()
            progress.update(total_task, completed=34)

            # Stage 5: SMS / iMessage & TypedStream Decoder (34 -> 44%)
            progress.update(total_task, description="[bold cyan]Stage 5/12: Carving sms.db & decoding iOS 16/17/18+ NSAttributedString streams...", completed=38)
            sms_path = self.manifest_resolver.find_file(filename="sms.db")
            sms_parser = SMSParser(sms_path)
            self.extracted_data["messages"] = sms_parser.parse()
            progress.update(total_task, completed=44)

            # Stage 6: Call History & Voice Telemetry (44 -> 54%)
            progress.update(total_task, description="[bold cyan]Stage 6/12: Extracting CallHistory.storedata & computing duration metrics...", completed=48)
            calls_path = self.manifest_resolver.find_file(filename="CallHistory.storedata")
            calls_parser = CallsParser(calls_path)
            raw_calls = calls_parser.parse()
            for c in raw_calls:
                if c.get("contact_name") == "Unknown" and c.get("number"):
                    c["contact_name"] = contacts_parser.resolve_number(c["number"])
            self.extracted_data["calls"] = raw_calls
            progress.update(total_task, completed=54)

            # Stage 7: Apple Notes & Protobuf Decompilation (54 -> 64%)
            progress.update(total_task, description="[bold cyan]Stage 7/12: Decompressing Gzip blobs & parsing NoteStore.sqlite Protobufs...", completed=58)
            notes_path = self.manifest_resolver.find_file(filename="NoteStore.sqlite")
            notes_parser = NotesParser(notes_path)
            self.extracted_data["notes"] = notes_parser.parse()
            progress.update(total_task, completed=64)

            # Stage 8: WhatsApp & Instant Messaging (64 -> 72%)
            progress.update(total_task, description="[bold cyan]Stage 8/12: Decoding WhatsApp ChatStorage.sqlite & Group Messages...", completed=68)
            wa_path = self.manifest_resolver.find_file(filename="ChatStorage.sqlite")
            wa_parser = WhatsAppParser(wa_path)
            self.extracted_data["whatsapp"] = wa_parser.parse()
            progress.update(total_task, completed=72)

            # Stage 9: Enterprise & Cloud Messaging (72 -> 80%)
            progress.update(total_task, description="[bold cyan]Stage 9/12: Carving Telegram, Signal, Microsoft Teams & ProtonMail...", completed=76)
            ent_parser = EnterpriseAppsParser(self.manifest_resolver)
            self.extracted_data["enterprise_apps"] = ent_parser.parse()
            progress.update(total_task, completed=80)

            # Stage 10: Audio Recordings & Voice Memos (80 -> 87%)
            progress.update(total_task, description="[bold cyan]Stage 10/12: Carving Voice Memos, Voicemails, and Audio Streams...", completed=83)
            rec_parser = RecordingsParser(manifest_resolver=self.manifest_resolver, contacts_parser=contacts_parser)
            self.extracted_data["recordings"] = rec_parser.parse()
            progress.update(total_task, completed=87)

            # Stage 11: Safari & Financial Super-Timeline (87 -> 94%)
            progress.update(total_task, description="[bold cyan]Stage 11/12: Parsing Safari History, DataUsage & Constructing Timeline...", completed=90)
            safari_path = self.manifest_resolver.find_file(filename="SafariHistory.db")
            safari_parser = SafariParser(safari_path)
            self.extracted_data["safari"] = safari_parser.parse()

            data_usage_path = self.manifest_resolver.find_file(filename="DataUsage.sqlite")
            du_parser = DataUsageParser(data_usage_path)
            self.extracted_data["app_usage"] = du_parser.parse()

            fin_parser = FinancialParser(messages=self.extracted_data["messages"], notes=self.extracted_data["notes"])
            self.extracted_data["financial"] = fin_parser.parse()

            timeline_engine = TimelineEngine()
            timeline_engine.ingest_sms(self.extracted_data["messages"])
            timeline_engine.ingest_calls(self.extracted_data["calls"])
            timeline_engine.ingest_notes(self.extracted_data["notes"])
            timeline_engine.ingest_safari(self.extracted_data["safari"])
            self.extracted_data["timeline"] = timeline_engine.build_timeline()
            progress.update(total_task, completed=94)

            # Stage 12: Generate DOCX & HTML Reports (94 -> 100%)
            progress.update(total_task, description="[bold cyan]Stage 12/12: Compiling Court-Ready DOCX and Interactive HTML Intelligence Reports...", completed=97)
            meta = self.manifest_resolver.get_summary()

            docx_exp = DocxReportExporter(
                metadata=meta,
                messages=self.extracted_data["messages"],
                calls=self.extracted_data["calls"],
                notes=self.extracted_data["notes"],
                contacts=self.extracted_data["contacts"],
                financial=self.extracted_data["financial"],
                app_usage=self.extracted_data["app_usage"],
                recordings=self.extracted_data["recordings"],
                enterprise_apps=self.extracted_data["enterprise_apps"],
                custody_manifest=self.extracted_data["custody_manifest"],
                keychain=self.extracted_data["keychain"]
            )
            docx_path = os.path.join(self.output_storage_dir, f"iOS_Forensic_Intelligence_Report_{meta.get('udid', 'Case')[:16]}.docx")
            docx_exp.generate(docx_path)

            html_exp = HTMLDashboardExporter(
                metadata=meta,
                messages=self.extracted_data["messages"],
                calls=self.extracted_data["calls"],
                notes=self.extracted_data["notes"],
                contacts=self.extracted_data["contacts"],
                financial=self.extracted_data["financial"],
                app_usage=self.extracted_data["app_usage"],
                recordings=self.extracted_data["recordings"],
                enterprise_apps=self.extracted_data["enterprise_apps"],
                custody_manifest=self.extracted_data["custody_manifest"],
                keychain=self.extracted_data["keychain"]
            )
            html_path = os.path.join(self.output_storage_dir, "Interactive_Forensic_Dashboard.html")
            html_exp.generate(html_path)

            # Export structured plain-text & decrypted folder trees
            progress.update(total_task, description="[bold cyan]Stage 12/12: Exporting Plain-Text & Categorized Folder Tree...", completed=99)
            plain_exp = PlainTextTreeExporter(
                output_base_dir=self.output_storage_dir,
                extracted_data=self.extracted_data,
                metadata=meta,
                manifest_resolver=self.manifest_resolver
            )
            plain_exp.export_all()

            time.sleep(0.4)
            progress.update(total_task, completed=100, description="[bold green]✔ ENTERPRISE FULL FETCH COMPLETED SUCCESSFULLY!")

        self.display_fetch_summary(docx_path, html_path)

    def display_fetch_summary(self, docx_path, html_path):
        meta = self.manifest_resolver.get_summary()
        recs_count = self.extracted_data["recordings"].get("total_audio_artifacts", 0)
        ent_count = self.extracted_data["enterprise_apps"].get("total_enterprise_records", 0)
        kc_count = len(self.extracted_data.get("keychain", {}).get("all_decrypted_records", []))
        m_hash = self.extracted_data.get("custody_manifest", {}).get("master_hash", "Recorded")
        plain_evidence_dir = os.path.join(self.output_storage_dir, "01_Extracted_Plain_Evidence")

        table = Table(title="Enterprise Extraction & Intelligence Summary", box=box.HEAVY_EDGE, border_style="green")
        table.add_column("Forensic Artifact", style="bold white", width=30)
        table.add_column("Carved Records", style="bold cyan", justify="right")
        table.add_column("Status / Verification", style="green", justify="center")

        table.add_row("Evidence Chain of Custody", f"{self.extracted_data['custody_manifest'].get('file_count', 0):,} Files", "NIST CFTT Verified (SHA-256)")
        table.add_row("Messages (SMS / iMessage)", f"{len(self.extracted_data['messages']):,}", "Decoded (TypedStream)")
        table.add_row("Call Logs & Voice Telemetry", f"{len(self.extracted_data['calls']):,}", "Parsed (Duration+Status)")
        table.add_row("Apple Notes & Credentials", f"{len(self.extracted_data['notes']):,}", "Decompiled (Gzip+Protobuf)")
        table.add_row("Contacts & Truecaller Directory", f"{len(self.extracted_data['contacts']):,}", "Unified Graph")
        table.add_row("Enterprise Cloud Apps (TG/Teams)", f"{ent_count:,}", "Decoded & Correlated")
        table.add_row("Decrypted Keychain & Cryptographic Keys", f"{kc_count:,}", "Unwrapped (AES-256)")
        table.add_row("Voice Memos & Audio Recordings", f"{recs_count:,}", "Carved & Indexed")
        table.add_row("WhatsApp Messages", f"{len(self.extracted_data['whatsapp']):,}", "Parsed")
        table.add_row("Safari Web History", f"{len(self.extracted_data['safari']):,}", "Indexed")
        table.add_row("Financial Transactions & OTPs", f"{len(self.extracted_data['financial']):,}", "Ledger Generated")
        table.add_row("Master Chronological Timeline", f"{len(self.extracted_data['timeline']):,}", "Synthesized")

        console.print("\n")
        console.print(table)

        console.print(Panel(
            f"[bold green]✔ Executive Reports & Chain of Custody Ready:[/bold green]\n\n"
            f"[bold white]Storage Location:[/bold white] [yellow]{self.output_storage_dir}[/yellow]\n"
            f"[bold white]Plain Evidence Folder:[/bold white] [bold cyan]{plain_evidence_dir}[/bold cyan]\n"
            f"[bold white]Master SHA-256:[/bold white] [cyan]{m_hash}[/cyan]\n"
            f"[bold white]DOCX Report:[/bold white] [cyan]{docx_path}[/cyan]\n"
            f"[bold white]Interactive HTML Dashboard:[/bold white] [cyan]{html_path}[/cyan]\n"
            f"[bold white]Decrypted Keychain Secrets:[/bold white] [cyan]{os.path.join(self.output_storage_dir, 'Keychain_Decrypted_Secrets.json')}[/cyan]\n"
            f"[bold white]Chain of Custody Manifest:[/bold white] [cyan]{os.path.join(self.output_storage_dir, 'Chain_of_Custody_Manifest.txt')}[/cyan]",
            title="Evidence Reports & Integrity Verification", border_style="green"
        ))

        self.post_fetch_explorer(html_path)

    def post_fetch_explorer(self, html_path):
        while True:
            console.print("\n[bold cyan]Interactive Forensic Actions:[/bold cyan]")
            console.print("[bold yellow][1][/bold yellow] [bold green](Recommended)[/bold green] Universal Entity Search (Phone, Name, Email, Bank Keyword, Passwords)")
            console.print("[bold yellow][2][/bold yellow] [bold green](Recommended)[/bold green] Open Interactive HTML Dashboard in Browser")
            console.print("[bold yellow][3][/bold yellow] View Financial & Banking Transactions Ledger")
            console.print("[bold yellow][4][/bold yellow] View Top Call Frequency & Contact Graph")
            console.print("[bold yellow][5][/bold yellow] View Apple Notes & Carved Passwords/Credentials")
            console.print("[bold yellow][6][/bold yellow] View Voice Memos, Voicemails & Audio Recordings")
            console.print("[bold yellow][7][/bold yellow] View Enterprise & Secure Cloud Messaging (Telegram, Teams, Signal)")
            console.print("[bold yellow][8][/bold yellow] View Digital Evidence Chain of Custody & Cryptographic Hashes")
            console.print("[bold yellow][9][/bold yellow] View Decrypted iOS Keychain Secrets & Cryptographic Key Ring")
            console.print("[bold yellow][10][/bold yellow] View Cryptographic KeyBag Manifest & Escrow Telemetry")
            console.print("[bold yellow][0][/bold yellow] Return to Main Menu")

            act = Prompt.ask("\n[bold cyan]Select an action [0-10] (Default: 1 - Recommended Search)[/bold cyan]", default="1")
            if act == "0":
                break
            elif act == "1":
                query = Prompt.ask("[bold cyan]Enter search query or regex[/bold cyan]")
                self.perform_universal_search(query)
            elif act == "2":
                import webbrowser
                abs_html = os.path.abspath(html_path)
                try:
                    webbrowser.open(f"file://{abs_html}")
                    console.print(f"[bold green]✔ Opened dashboard in default browser:[/bold green] [cyan]{abs_html}[/cyan]")
                except Exception:
                    console.print(f"[bold yellow]Open manually in browser:[/bold yellow] [cyan]file://{abs_html}[/cyan]")
            elif act == "3":
                self.show_financial_ledger()
            elif act == "4":
                self.show_call_frequency()
            elif act == "5":
                self.show_notes_explorer()
            elif act == "6":
                self.show_recordings_explorer()
            elif act == "7":
                self.show_enterprise_apps_explorer()
            elif act == "8":
                self.show_chain_of_custody_explorer()
            elif act == "9":
                self.show_keychain_explorer()
            elif act == "10":
                self.show_keybag_explorer()

    def show_keybag_explorer(self):
        crypto = self.crypto_engine or (CryptoEngine(self.active_backup_dir) if self.active_backup_dir else None)
        if not crypto:
            console.print("[bold yellow]No active cryptographic engine initialized.[/bold yellow]")
            return

        summary = crypto.get_keybag_summary()
        t = Table(title="Cryptographic KeyBag Architecture & Derivation Parameters", box=box.ROUNDED, border_style="yellow")
        t.add_column("Cryptographic Parameter", style="bold white", width=28)
        t.add_column("KeyBag Parameter Value", style="bold yellow")

        t.add_row("Encryption Standard", "AES-256-CBC (RFC 3394 Key Wrap)")
        t.add_row("KeyBag UUID", str(summary.get("keybag_uuid")))
        t.add_row("KeyBag Type", str(summary.get("keybag_type")))
        t.add_row("Key Derivation Method", str(summary.get("kdf_method")))
        t.add_row("PBKDF2 Iteration Count", f"{summary.get('pbkdf2_iterations', 0):,}")
        t.add_row("Master Salt (Hex)", str(summary.get("salt_hex"))[:40] + "...")
        t.add_row("Total Protection Classes", f"{summary.get('total_classes_detected', 0)} Detected")
        t.add_row("Classes Unwrapped", f"[bold green]{summary.get('unwrapped_classes_count', 0)} Unwrapped[/bold green]")
        console.print(t)

        if summary.get("protection_classes"):
            t_cls = Table(title="Protection Class Ring & Access Control Status", box=box.ROUNDED, border_style="cyan")
            t_cls.add_column("Class ID", style="bold yellow", width=10)
            t_cls.add_column("Protection Class Name & Access Attribute", style="bold white")
            t_cls.add_column("Key Status", style="bold green", width=24)
            for c in summary["protection_classes"]:
                st = "[bold green]✔ UNWRAPPED & ACTIVE[/bold green]" if c["unwrapped"] else "[yellow]LOCKED (WRAPPED)[/yellow]"
                t_cls.add_row(f"Class {c['class_id']}", c["description"], st)
            console.print(t_cls)

        Prompt.ask("\n[bold cyan]Press Enter to continue[/bold cyan]")

    def show_keychain_explorer(self):
        kc = self.extracted_data.get("keychain", {})
        all_recs = kc.get("all_decrypted_records", [])
        if not all_recs:
            all_recs = (kc.get("web_credentials", []) + kc.get("wifi_networks", []) +
                        kc.get("app_tokens_and_keys", []) + kc.get("crypto_keys", []))

        if not all_recs:
            console.print("[bold yellow]No keychain secrets decrypted in this session.[/bold yellow]")
            return

        table = Table(title=f"Decrypted iOS Keychain Secrets & Cryptographic Keys ({len(all_recs):,} Total)", box=box.ROUNDED, border_style="purple")
        table.add_column("Category", style="bold purple", width=18)
        table.add_column("Service / Server", style="bold white", width=24)
        table.add_column("Account / SSID", style="cyan", width=22)
        table.add_column("Decrypted Secret / Key", style="bold yellow")
        table.add_column("Protection Class", style="dim", width=22)

        for rec in all_recs[:60]:
            c_type = rec.get("type", "Secret")
            srv = rec.get("service") or rec.get("server") or rec.get("label", "N/A")
            acct = rec.get("account", "N/A")
            val = rec.get("decrypted_password") or rec.get("decrypted_value") or rec.get("decrypted_key_payload", "")
            pclass = rec.get("protection_class", "N/A")
            table.add_row(c_type, srv[:24], acct[:22], str(val)[:45], pclass[:22])

        console.print(table)
        Prompt.ask("\n[bold cyan]Press Enter to continue[/bold cyan]")

    def perform_universal_search(self, query):
        q = query.lower()
        results = []

        for m in self.extracted_data["messages"]:
            if q in (m.get("text", "") + m.get("sender", "")).lower():
                results.append(("MESSAGE", m.get("timestamp_local"), m.get("sender"), m.get("text")[:100]))

        for c in self.extracted_data["calls"]:
            if q in (c.get("number", "") + c.get("contact_name", "") + c.get("status", "")).lower():
                results.append(("CALL", c.get("timestamp_local"), c.get("contact_name") or c.get("number"), f"{c.get('status')} ({c.get('duration_formatted')})"))

        for n in self.extracted_data["notes"]:
            if q in (n.get("title", "") + n.get("full_content", "")).lower():
                results.append(("NOTE", n.get("modified_local"), n.get("title"), n.get("snippet", "")[:100]))

        for f in self.extracted_data["financial"]:
            if q in (f.get("entity", "") + f.get("summary", "") + f.get("type", "")).lower():
                results.append(("FINANCIAL", f.get("timestamp_local"), f.get("entity"), f"{f.get('type')} | {f.get('amount')} | {f.get('summary')[:80]}"))

        kc_records = self.extracted_data.get("keychain", {}).get("all_decrypted_records", [])
        if not kc_records:
            kc_records = (self.extracted_data.get("keychain", {}).get("web_credentials", []) +
                          self.extracted_data.get("keychain", {}).get("wifi_networks", []) +
                          self.extracted_data.get("keychain", {}).get("app_tokens_and_keys", []) +
                          self.extracted_data.get("keychain", {}).get("crypto_keys", []))

        for k in kc_records:
            k_comb = (str(k.get("service", "")) + str(k.get("account", "")) + str(k.get("server", "")) +
                      str(k.get("url", "")) + str(k.get("access_group", "")) + str(k.get("decrypted_password", "")) +
                      str(k.get("decrypted_value", "")) + str(k.get("decrypted_key_payload", ""))).lower()
            if q in k_comb:
                srv = k.get("service") or k.get("server") or k.get("label") or "Keychain Secret"
                val = k.get("decrypted_password") or k.get("decrypted_value") or k.get("decrypted_key_payload") or ""
                results.append(("KEYCHAIN", k.get("modification_date") or k.get("creation_date") or "N/A", f"{srv} ({k.get('account', 'N/A')})", f"Secret: {str(val)[:80]}"))

        if not results:
            console.print(f"[bold yellow]No matching records found for '{query}'.[/bold yellow]")
            return

        table = Table(title=f"Search Results for '{query}' ({len(results)} matches)", box=box.ROUNDED, border_style="cyan")
        table.add_column("Type", style="bold yellow", width=12)
        table.add_column("Timestamp", style="dim", width=22)
        table.add_column("Actor / Entity", style="bold white", width=22)
        table.add_column("Extracted Snippet", style="cyan")

        for r in results[:50]:
            table.add_row(r[0], r[1] or "N/A", r[2] or "Unknown", r[3] or "")

        console.print(table)

    def show_call_frequency(self):
        from collections import Counter
        counts = Counter()
        durations = {}

        for c in self.extracted_data["calls"]:
            actor = c.get("contact_name") if c.get("contact_name") != "Unknown" else c.get("number")
            if actor:
                counts[actor] += 1
                durations[actor] = durations.get(actor, 0) + c.get("duration_seconds", 0)

        table = Table(title="Top Communication Frequency & Duration Graph", box=box.ROUNDED, border_style="cyan")
        table.add_column("Contact / Number", style="bold white")
        table.add_column("Total Calls", style="bold cyan", justify="right")
        table.add_column("Cumulative Duration", style="bold green", justify="right")

        for actor, count in counts.most_common(15):
            from parsers.calls_parser import format_duration
            table.add_row(actor, str(count), format_duration(durations.get(actor, 0)))

        console.print(table)

    def show_financial_ledger(self):
        if not self.extracted_data["financial"]:
            console.print("[bold yellow]No financial records extracted.[/bold yellow]")
            return

        table = Table(title=f"Extracted Financial & Banking Ledger ({len(self.extracted_data['financial'])} events)", box=box.ROUNDED, border_style="cyan")
        table.add_column("Timestamp", style="dim", width=20)
        table.add_column("Entity / Bank", style="bold white", width=18)
        table.add_column("Type", style="bold yellow", width=16)
        table.add_column("Amount", style="bold green", width=14)
        table.add_column("Summary", style="cyan")

        for f in self.extracted_data["financial"][:30]:
            table.add_row(f.get("timestamp_local"), f.get("entity"), f.get("type"), f.get("amount"), f.get("summary")[:70])

        console.print(table)

    def show_notes_explorer(self):
        if not self.extracted_data["notes"]:
            console.print("[bold yellow]No notes extracted.[/bold yellow]")
            return

        for n in self.extracted_data["notes"][:15]:
            tag_str = f" [bold red][{', '.join(n['tags'])}][/bold red]" if n.get("tags") else ""
            console.print(Panel(
                f"[bold cyan]{n.get('title')}[/bold cyan]{tag_str}\n"
                f"[dim]Folder: {n.get('folder')} | Modified: {n.get('modified_local')}[/dim]\n\n"
                f"[white]{n.get('full_content')[:400]}[/white]",
                border_style="blue"
            ))

    def show_recordings_explorer(self):
        recs = self.extracted_data.get("recordings", {})
        voice_memos = recs.get("voice_memos", [])
        voicemails = recs.get("voicemails", [])
        audio_files = recs.get("carved_audio_files", [])

        if not voice_memos and not voicemails and not audio_files:
            console.print("[bold yellow]No audio recordings or voice memos discovered in this evidence.[/bold yellow]")
            return

        if voice_memos:
            t_memos = Table(title=f"Apple Voice Memos ({len(voice_memos)} items)", box=box.ROUNDED, border_style="cyan")
            t_memos.add_column("Title / Label", style="bold white")
            t_memos.add_column("Duration", justify="right", style="bold green")
            t_memos.add_column("Recorded Date (Local)", style="dim")
            t_memos.add_column("Status", style="yellow")
            for m in voice_memos[:20]:
                t_memos.add_row(m.get("title"), f"{m.get('duration_seconds')}s", m.get("timestamp_local"), "[red]Deleted[/red]" if m.get("deleted") else "[green]Active[/green]")
            console.print(t_memos)

        if voicemails:
            t_vm = Table(title=f"Voicemails ({len(voicemails)} items)", box=box.ROUNDED, border_style="magenta")
            t_vm.add_column("Caller / Contact", style="bold white")
            t_vm.add_column("Number", style="cyan")
            t_vm.add_column("Duration", justify="right", style="green")
            t_vm.add_column("Timestamp", style="dim")
            t_vm.add_column("Transcription Snippet", style="white")
            for v in voicemails[:20]:
                t_vm.add_row(v.get("caller_name"), v.get("sender"), f"{v.get('duration_seconds')}s", v.get("timestamp_local"), v.get("transcription")[:60])
            console.print(t_vm)

        if audio_files:
            t_aud = Table(title=f"Carved Raw Audio Files ({len(audio_files)} files)", box=box.ROUNDED, border_style="yellow")
            t_aud.add_column("Filename", style="bold white")
            t_aud.add_column("Format", style="cyan")
            t_aud.add_column("Size (KB)", justify="right", style="green")
            t_aud.add_column("Absolute Storage Path", style="dim")
            for a in audio_files[:15]:
                t_aud.add_row(a.get("filename"), a.get("extension"), str(a.get("size_kb")), a.get("path")[:60])
            console.print(t_aud)

    def show_enterprise_apps_explorer(self):
        ent = self.extracted_data.get("enterprise_apps", {})
        tg = ent.get("telegram", [])
        teams = ent.get("teams", [])
        signal = ent.get("signal", [])
        proton = ent.get("protonmail", [])

        total = len(tg) + len(teams) + len(signal) + len(proton)
        if total == 0:
            console.print("[bold yellow]No Telegram, Signal, Teams, or ProtonMail artifacts discovered in this backup.[/bold yellow]")
            return

        if tg:
            t_tg = Table(title=f"Telegram Messenger ({len(tg)} messages)", box=box.ROUNDED, border_style="blue")
            t_tg.add_column("Timestamp (Local)", style="dim", width=20)
            t_tg.add_column("Sender / User ID", style="bold cyan", width=18)
            t_tg.add_column("Chat ID", style="bold white", width=16)
            t_tg.add_column("Message Payload", style="white")
            for m in tg[:25]:
                t_tg.add_row(m.get("timestamp_local"), str(m.get("from_id")), str(m.get("chat_id")), m.get("text")[:80])
            console.print(t_tg)

        if teams:
            t_teams = Table(title=f"Microsoft Teams ({len(teams)} messages)", box=box.ROUNDED, border_style="magenta")
            t_teams.add_column("Timestamp (Local)", style="dim", width=20)
            t_teams.add_column("Sender", style="bold white", width=20)
            t_teams.add_column("Channel / Thread", style="cyan", width=20)
            t_teams.add_column("Message Body", style="white")
            for tm in teams[:25]:
                t_teams.add_row(tm.get("timestamp_local"), str(tm.get("sender")), str(tm.get("channel")), tm.get("text")[:80])
            console.print(t_teams)

        if signal:
            t_sig = Table(title=f"Signal Private Messenger Accounts & Sessions ({len(signal)} records)", box=box.ROUNDED, border_style="green")
            t_sig.add_column("Profile / Name", style="bold white")
            t_sig.add_column("Phone Number", style="bold cyan")
            t_sig.add_column("UUID", style="dim")
            for s in signal[:20]:
                t_sig.add_row(s.get("name"), s.get("phone"), s.get("id"))
            console.print(t_sig)

    def show_chain_of_custody_explorer(self):
        custody = self.extracted_data.get("custody_manifest", {})
        if not custody:
            console.print("[bold yellow]No Chain of Custody manifest generated yet.[/bold yellow]")
            return

        table = Table(title="Digital Evidence Chain of Custody (NIST CFTT Standard)", box=box.ROUNDED, border_style="cyan")
        table.add_column("Integrity Parameter", style="bold white", width=26)
        table.add_column("Verification Value", style="bold green")

        table.add_row("Master Evidence SHA-256", custody.get("master_hash", "N/A"))
        table.add_row("Total Files Verified", f"{custody.get('file_count', 0):,} evidence artifacts")
        table.add_row("Total Data Ingested", f"{custody.get('total_size_mb', 0):,} MB")
        table.add_row("JSON Verification Log", str(custody.get("json_manifest", "N/A")))
        table.add_row("Court Manifest (TXT)", str(custody.get("txt_manifest", "N/A")))
        table.add_row("Compliance Standard", "NIST CFTT / ISO/IEC 27037:2012")

        console.print(table)

    def main_loop(self):
        while True:
            self.print_banner()
            console.print(Panel(
                "[bold white]MAIN FORENSIC OPERATION MENU[/bold white]\n\n"
                "[bold yellow][1][/bold yellow] [bold green](Recommended for Rapid Triage)[/bold green] ⚡ Quick Selective Fetch (Pick Presets or Custom Modules)\n"
                "[bold yellow][2][/bold yellow] [bold cyan](Recommended for Complete Court Evidence)[/bold cyan] 🔬 100% Full Deep Forensic Acquisition & Full Carve\n"
                "[bold yellow][3][/bold yellow] 1-Click Autonomous Auto-Fetch (Detect USB / Local Evidence)\n"
                "[bold yellow][4][/bold yellow] Live USB Hardware Diagnostics & Lockdown Pairing Wizard\n"
                "[bold yellow][5][/bold yellow] Ingest Existing iOS Backup / Evidence Directory\n"
                "[bold yellow][6][/bold yellow] Universal Entity Search & Multi-Database Grep\n"
                "[bold yellow][7][/bold yellow] View System Environment & Storage Diagnostics\n"
                "[bold yellow][8][/bold yellow] Unlisted App & Custom SQLite Schema Inspector\n"
                "[bold yellow][9][/bold yellow] Autonomous Troubleshooter & Self-Healing Diagnostics\n"
                "[bold yellow][10][/bold yellow] [bold magenta]🔓 Decrypt & Unlock Stored Encrypted Evidence (KeyBag + Passphrase)[/bold magenta]\n"
                "[bold yellow][0][/bold yellow] Exit Forensic Suite",
                border_style="cyan"
            ))

            choice = Prompt.ask("[bold cyan]Enter option [0-10] (Default: 1 - Recommended Quick Selective Fetch)[/bold cyan]", default="1")
            if choice == "0":
                console.print("\n[bold green]Exiting iForensic. Forensic integrity preserved.[/bold green]")
                sys.exit(0)
            elif choice == "1":
                if not self.active_backup_dir:
                    self.load_existing_backup(target_fetch_mode="selective")
                else:
                    self.run_selective_fetch()
            elif choice == "2":
                if not self.active_backup_dir:
                    self.load_existing_backup(target_fetch_mode="full")
                else:
                    self.run_full_fetch()
            elif choice == "3":
                self.run_1click_auto_fetch()
            elif choice == "4":
                self.menu_device_diagnostics()
            elif choice == "5":
                self.load_existing_backup(target_fetch_mode="full")
            elif choice == "6":
                if not self.extracted_data["messages"] and not self.extracted_data["calls"]:
                    console.print("[bold red]Please execute a Quick or Full Fetch first to populate search index.[/bold red]")
                    Prompt.ask("\n[bold cyan]Press Enter to continue[/bold cyan]")
                else:
                    q = Prompt.ask("[bold cyan]Enter search query[/bold cyan]")
                    self.perform_universal_search(q)
                    Prompt.ask("\n[bold cyan]Press Enter to continue[/bold cyan]")
            elif choice == "7":
                self.print_banner()
                env = DeviceDetector.check_environment()
                t = Table(title="Forensic Toolchain & Environment Diagnostics", box=box.ROUNDED)
                t.add_column("Tool / Daemon", style="bold white")
                t.add_column("System Status", style="cyan")
                for k, v in env.items():
                    t.add_row(k, "[bold green]✔ Installed & Operational[/bold green]" if v else "[bold red]❌ Missing[/bold red]")
                console.print(t)

                exts = StorageManager.list_external_storage()
                t_ext = Table(title="Attached Storage & Removable Media", box=box.ROUNDED, border_style="yellow")
                t_ext.add_column("Device / Label", style="bold white")
                t_ext.add_column("Path", style="cyan")
                t_ext.add_column("Total Size", justify="right")
                t_ext.add_column("Free Space", justify="right")
                t_ext.add_column("Recommendation / Status", style="green")

                if exts:
                    for e in exts:
                        t_ext.add_row(e.get("label"), e.get("path"), f"{e.get('size_gb')} GB", f"{e.get('free_gb')} GB", f"Mounted: {e.get('is_mounted')}")
                else:
                    t_ext.add_row("No external storage currently attached", "N/A", "-", "-", "[yellow]None[/yellow]")
                console.print(t_ext)

                Prompt.ask("\n[bold cyan]Press Enter to return[/bold cyan]")
            elif choice == "8":
                self.menu_unlisted_app_inspector()
            elif choice == "9":
                from core.troubleshooter import AutonomousTroubleshooter
                self.print_banner()
                with console.status("[bold cyan]Running comprehensive autonomous diagnostics & self-repair...", spinner="dots"):
                    time.sleep(1.0)
                    healthy, repairs, issues = AutonomousTroubleshooter.run_automated_diagnostics_and_repair(verbose=True)
                
                if repairs:
                    t_r = Table(title="Autonomous Self-Healing Actions Applied", box=box.ROUNDED, border_style="green")
                    t_r.add_column("Repaired Component", style="bold green")
                    for r in repairs:
                        t_r.add_row(f"✔ {r}")
                    console.print(t_r)

                if issues:
                    t_i = Table(title="Unresolved Diagnostic Warnings", box=box.ROUNDED, border_style="yellow")
                    t_i.add_column("Warning / Diagnostic Item", style="bold yellow")
                    for i in issues:
                        t_i.add_row(f"⚠️ {i}")
                    console.print(t_i)
                elif not repairs:
                    console.print("[bold green]✔ All system subsystems, sockets, and dependencies are operational and healthy![/bold green]")
                
                Prompt.ask("\n[bold cyan]Press Enter to return to main menu[/bold cyan]")
            elif choice == "10":
                self.menu_decrypt_stored_evidence()

    def menu_decrypt_stored_evidence(self):
        self.print_banner()
        console.print(Panel(
            "[bold cyan]🔓 DECRYPT & UNLOCK STORED EVIDENCE WITH CRYPTOGRAPHIC KEYBAG[/bold cyan]\n\n"
            "[white]Unlock an existing encrypted iOS backup using its extracted KeyBag and passphrase.[/white]\n"
            "[dim]Derives keys, unwraps Protection Classes 1-11, decrypts Manifest.db, and exports full plain-text trees.[/dim]",
            border_style="cyan"
        ))

        if not self.active_backup_dir:
            self.load_existing_backup(target_fetch_mode="full")
            if not self.active_backup_dir:
                return

        crypto = CryptoEngine(self.active_backup_dir)
        if not crypto.is_encrypted:
            console.print("[bold green]✔ Selected evidence backup is already unencrypted (Plaintext).[/bold green]")
            if Confirm.ask("[bold cyan]Would you like to run Full Deep Extraction now?[/bold cyan]", default=True):
                self.run_full_fetch()
            return

        dec_manifest = self.handle_decryption_if_needed(force_prompt=True)
        if dec_manifest:
            console.print("\n[bold green]✔ Cryptographic keys unlocked! Ready for evidence extraction.[/bold green]\n")
            c = Prompt.ask("[bold cyan]Select Extraction Mode: [1] (Recommended) Full Deep Forensic Carve | [2] Quick Selective Fetch | [0] Return[/bold cyan]", default="1")
            if c == "1":
                self.run_full_fetch()
            elif c == "2":
                self.run_selective_fetch()
        else:
            console.print("[bold yellow]Decryption deferred or not completed.[/bold yellow]")
            Prompt.ask("\n[bold cyan]Press Enter to return to main menu[/bold cyan]")

    def menu_unlisted_app_inspector(self):
        if not self.active_backup_dir or not os.path.exists(self.active_backup_dir):
            console.print("[bold red]Please select or load an evidence backup directory first (Option 5).[/bold red]")
            Prompt.ask("\n[bold cyan]Press Enter to return[/bold cyan]")
            return

        self.print_banner()
        console.print(Panel("[bold yellow]UNLISTED APPLICATION & AD-HOC SQLITE DATABASE INSPECTOR[/bold yellow]", border_style="yellow"))

        with console.status("[bold cyan]Scanning evidence folder for all SQLite databases...", spinner="dots"):
            dbs = UniversalAppEngine.list_all_discovered_databases(self.active_backup_dir)

        if not dbs:
            console.print("[bold yellow]No SQLite databases discovered in current evidence.[/bold yellow]")
            Prompt.ask("\n[bold cyan]Press Enter to return[/bold cyan]")
            return

        table = Table(title=f"Discovered Databases ({len(dbs)} files)", box=box.ROUNDED, border_style="cyan")
        table.add_column("#", style="bold yellow", width=5)
        table.add_column("Database Path (Relative)", style="cyan")
        table.add_column("Size (KB)", justify="right", style="green", width=12)
        table.add_column("Tables", style="bold white", width=10)

        for idx, db in enumerate(dbs[:30], 1):
            table.add_row(str(idx), db["relative_path"][:50], str(db["size_kb"]), str(db["table_count"]))

        console.print(table)
        console.print("[bold white][0][/bold white] Return to Main Menu\n")

        db_choice = Prompt.ask("[bold cyan]Select database # to inspect schema[/bold cyan]", default="0")
        if db_choice == "0":
            return

        try:
            sel_idx = int(db_choice) - 1
            if 0 <= sel_idx < len(dbs):
                target_db = dbs[sel_idx]
                schema = UniversalAppEngine.inspect_database_schema(target_db["path"])
                if schema:
                    t_schema = Table(title=f"Schema for {target_db['filename']}", box=box.ROUNDED, border_style="green")
                    t_schema.add_column("Table Name", style="bold white")
                    t_schema.add_column("Rows", justify="right", style="bold cyan")
                    t_schema.add_column("Columns", style="yellow")
                    for tbl, info in schema.items():
                        t_schema.add_row(tbl, f"{info['row_count']:,}", ", ".join(info["columns"][:6]))
                    console.print(t_schema)
                Prompt.ask("\n[bold cyan]Press Enter to return[/bold cyan]")
        except ValueError:
            pass

def main():
    parser = argparse.ArgumentParser(description="iForensic - Enterprise iOS Digital Forensics Suite")
    parser.add_argument("--auto", "-a", action="store_true", help="1-Click Auto Mode: Auto-detect, auto-pair, carve, and generate reports in one command")
    parser.add_argument("--full", "-f", action="store_true", help="100%% Full Deep Forensic Acquisition & Complete Bitstream Carving")
    parser.add_argument("--quick", "-q", action="store_true", help="⚡ Quick Triage Mode: Fast extraction of high-value communications, notes, and financial records (<5s)")
    parser.add_argument("--targets", "-t", type=str, help="Comma-separated list of target modules (e.g. 'messages,calls,notes,whatsapp,financial')")
    parser.add_argument("--backup", "-b", type=str, help="Directly ingest and parse an existing iOS backup folder")
    parser.add_argument("--output", "-o", type=str, help="Custom destination directory for evidence & reports")
    parser.add_argument("--password", "-p", type=str, help="Passphrase for encrypted iOS backups (AES-256 / PBKDF2 / scrypt)")
    args = parser.parse_args()

    try:
        if args.backup:
            app = iForensicCLI(automated_mode=True, password=args.password)
            app.active_backup_dir = os.path.abspath(args.backup)
            if args.output:
                app.output_storage_dir = os.path.abspath(args.output)
            
            if args.targets:
                target_set = set(t.strip().lower() for t in args.targets.split(",") if t.strip())
                app.run_selective_fetch(selected_targets=target_set)
            elif args.quick:
                app.run_selective_fetch(selected_targets={"messages", "calls", "contacts", "notes", "whatsapp", "enterprise", "financial"})
            else:
                app.run_full_fetch()

        elif args.quick:
            app = iForensicCLI(automated_mode=True, password=args.password)
            if args.output:
                app.output_storage_dir = os.path.abspath(args.output)
            # Find candidate backup or run quick fetch
            candidates = [
                "/home/lazzy/iphone-test/backup-full/00008110-00184DC63CD3801E",
                "/home/lazzy/Desktop/ios_forensics_cases/00008110-00184DC63CD3801E_20260930_204604",
                "/home/lazzy/iphone-test/backup-full"
            ]
            for c in candidates:
                if os.path.exists(c):
                    app.active_backup_dir = c
                    break
            if app.active_backup_dir:
                app.run_selective_fetch(selected_targets={"messages", "calls", "contacts", "notes", "whatsapp", "enterprise", "financial"})
            else:
                app.run_1click_auto_fetch()

        elif args.auto or args.full:
            app = iForensicCLI(automated_mode=True, password=args.password)
            if args.output:
                app.output_storage_dir = os.path.abspath(args.output)
            app.run_1click_auto_fetch()
        else:
            app = iForensicCLI(password=args.password)
            app.main_loop()
    except KeyboardInterrupt:
        console.print("\n\n[bold yellow][!] Forensic operation interrupted by user. Exiting cleanly.[/bold yellow]")
        sys.exit(0)

if __name__ == "__main__":
    main()
