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
from core.audit_logger import ForensicAuditLogger
from core.sqlite_freelist_carver import SQLiteFreelistCarver
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
from exporters.plain_text_tree_exporter import PlainTextTreeExporter
from exporters.bulk_data_exporter import BulkDataExporter

console = Console()

BANNER = """[bold cyan]
  ██╗███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗
  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝
  ██║█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     
  ██║██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     
  ██║██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗
  ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝
[/bold cyan]
  [bold white]Next-Gen iPhone Data Extractor & Forensic Tool[/bold white]
  [bold green]Developed by LazZy[/bold green] [dim]| Lead Dev: ANUDITKHATRI2011@GMAIL.COM[/dim]
  [dim]Extracts: Messages, Calls, Photos, Notes, Passwords, WhatsApp & Financial Records[/dim]
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
        self.audit_logger = None
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
            "deleted_carved_records": [],
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

        table = Table(title="Password-Protected (Encrypted) iPhone Backup Detected", box=box.ROUNDED, border_style="yellow")
        table.add_column("Security Setting", style="bold white", width=28)
        table.add_column("Details", style="bold yellow")

        table.add_row("Encryption Status", "Locked with AES-256 Passcode")
        table.add_row("Lock Identifier (UUID)", str(kb_summary.get("keybag_uuid"))[:24] + "...")
        table.add_row("Key Derivation Algorithm", str(kb_summary.get("kdf_method")))
        table.add_row("Protection Layers Found", f"{kb_summary.get('total_classes_detected', 0)} Security Layers")
        console.print(table)

        if not self.backup_password and not self.automated_mode and not force_prompt:
            decrypt_choice = Confirm.ask("\n[bold green]This backup is password-protected. Would you like to enter the password to unlock all data in plain text? (Recommended)[/bold green]", default=True)
            if not decrypt_choice:
                console.print("[bold yellow][OK] Decryption deferred. Encrypted backup files are safely preserved.[/bold yellow]")
                console.print("[dim]You can unlock this backup anytime during extraction or by launching with '--password <pass>'.[/dim]\n")
                if self.output_storage_dir:
                    crypto.export_keybag_manifest(os.path.join(self.output_storage_dir, "Cryptographic_KeyBag_Manifest.txt"))
                return None

        pwd = self.backup_password
        max_tries = 3 if not pwd else 1

        for attempt in range(1, max_tries + 1):
            if not pwd:
                pwd = Prompt.ask("[bold cyan]Enter iPhone Backup Password (or press Enter to skip)[/bold cyan]", password=True)
                if not pwd:
                    console.print("[bold yellow]Skipping password unlock. Processing only unencrypted files.[/bold yellow]")
                    if self.output_storage_dir:
                        crypto.export_keybag_manifest(os.path.join(self.output_storage_dir, "Cryptographic_KeyBag_Manifest.txt"))
                    return None

            with console.status("[bold cyan]Unlocking encryption keys and decrypting data...", spinner="dots"):
                success, msg = crypto.verify_and_unlock(pwd)

            if success:
                console.print(f"[bold green][OK] Password correct! All data successfully unlocked.[/bold green]")
                stg_dir = self.output_storage_dir or os.path.join(self.active_backup_dir, "decrypted_staging")
                os.makedirs(stg_dir, exist_ok=True)
                dec_manifest = os.path.join(stg_dir, "Manifest_decrypted.db")
                dec_ok, dec_msg = crypto.decrypt_manifest_db(dec_manifest)
                if dec_ok:
                    console.print(f"[bold green][OK] Database index decrypted and ready for reading![/bold green]")
                    self.decrypted_manifest_path = dec_manifest
                    self.crypto_engine = crypto
                    crypto.export_keybag_manifest(os.path.join(stg_dir, "Cryptographic_KeyBag_Manifest.txt"))
                    if self.output_storage_dir:
                        crypto.export_keybag_manifest(os.path.join(self.output_storage_dir, "Cryptographic_KeyBag_Manifest.txt"))
                    return dec_manifest
                else:
                    console.print(f"[bold red][ERROR] {dec_msg}[/bold red]")
                    return None
            else:
                console.print(f"[bold red][ERROR] Incorrect password (Attempt {attempt}/{max_tries}). Please try again.[/bold red]")
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
            "[bold cyan]WHERE DO YOU WANT TO SAVE THE EXTRACTED EVIDENCE & REPORTS?[/bold cyan]\n\n"
            "[bold yellow][1][/bold yellow] [bold green](Recommended — Fast)[/bold green] [bold white]Internal Computer Storage[/bold white]\n"
            "    [dim]↳ Saves to Desktop: ~/Desktop/ios_forensics_cases/iforensic_{case_name}[/dim]\n\n"
            "[bold yellow][2][/bold yellow] [bold cyan]External USB Hard Drive / Flash Drive[/bold cyan]\n"
            "    [dim]↳ Automatically detects and saves directly to your plugged-in USB storage drive[/dim]\n\n"
            "[bold yellow][3][/bold yellow] [bold white]Custom Folder Path[/bold white]\n"
            "    [dim]↳ Enter any custom local or network folder[/dim]",
            title="Save Destination", border_style="cyan"
        ))

        choice = Prompt.ask("[bold cyan]Select save location [1-3] (Default: 1 - Internal Storage)[/bold cyan]", default="1")

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
                    "[bold red][ERROR] No External USB Storage Device Detected[/bold red]\n\n"
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
                m_status = f"[green][OK] (Recommended) Mounted[/green]" if dev.get("is_mounted") else "[yellow]Unmounted (Auto-Mountable)[/yellow]"
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
                            console.print(f"[bold green][OK] Storage Target Configured at:[/bold green] [cyan]{mount_dir}[/cyan]")
                            target_dir = os.path.join(mount_dir, "iforensic_evidence", f"case_{case_name}")
                            os.makedirs(target_dir, exist_ok=True)
                            time.sleep(1.0)
                            return target_dir
                        else:
                            console.print(f"[bold red][ERROR] Failed to mount device: {mount_dir}[/bold red]")
                            time.sleep(1.5)
                except ValueError:
                    pass

    def carve_freelist_data(self):
        """
        Scans all key forensic SQLite databases for freelist pages and unallocated cell areas,
        recovering deleted text fragments, orphaned messages, notes, and contacts.
        """
        if not self.manifest_resolver:
            return []
        
        target_dbs = [
            ("Messages (sms.db)", self.manifest_resolver.find_file("Library/SMS/sms.db") or self.manifest_resolver.find_file("sms.db")),
            ("WhatsApp (ChatStorage.sqlite)", self.manifest_resolver.find_file("ChatStorage.sqlite") or self.manifest_resolver.find_file("AppDomainGroup-group.net.whatsapp.WhatsApp.shared", "ChatStorage.sqlite")),
            ("Apple Notes (NoteStore.sqlite)", self.manifest_resolver.find_file("NoteStore.sqlite")),
            ("Contacts (AddressBook.sqlitedb)", self.manifest_resolver.find_file("AddressBook.sqlitedb"))
        ]
        
        carved_all = []
        for name, db_path in target_dbs:
            if db_path and os.path.exists(db_path):
                records = SQLiteFreelistCarver.carve_deleted_records(db_path, min_length=4, max_records=100)
                for r in records:
                    r["database_name"] = name
                    carved_all.append(r)
        
        self.extracted_data["deleted_carved_records"] = carved_all
        if self.audit_logger:
            self.audit_logger.log_event("FREELIST_CARVING_COMPLETED", {"total_fragments_carved": len(carved_all)})
        return carved_all

    def run_1click_auto_fetch(self):
        """
        One-Command Unified Pipeline (Auto-Detect -> Auto-Pair -> Auto-Select Storage -> Full Carve -> Report).
        """
        self.print_banner()
        console.print(Panel(
            "[bold green]1-COMMAND COMPLETE AUTONOMOUS FORENSIC PIPELINE[/bold green]\n"
            "[dim]Auto-detecting hardware, lockdown pairing, evidence resolution, and full artifact carving...[/dim]",
            border_style="green"
        ))

        # 1. Detect USB Hardware
        with console.status("[bold cyan]Step 1/4: Checking connected USB iOS hardware...", spinner="dots"):
            time.sleep(0.8)
            udids = DeviceDetector.detect_connected_devices()

        if udids:
            target_udid = udids[0]
            console.print(f"[bold green][OK] iOS Device Connected via USB:[/bold green] [cyan]{target_udid}[/cyan]")
            
            # Check pairing
            is_paired, _ = DeviceDetector.validate_pairing(target_udid)
            if not is_paired:
                console.print("[bold yellow][WARNING] Pairing with connected device... Unlock iPhone & tap 'Trust'[/bold yellow]")
                DeviceDetector.pair_device(target_udid)

            dev_info = DeviceDetector.get_device_info(target_udid)
            case_id = (dev_info.get("device_name", "iphone") + "_" + target_udid[:8]) if dev_info else target_udid[:8]
            dest_dir = self.select_storage_target(case_name=case_id)
            self.output_storage_dir = dest_dir
            self.run_live_acquisition(target_udid, dev_info.get("device_name") if dev_info else "iPhone", dest_dir)
            return

        # 2. If no live USB, attempt usbmuxd self-healing and prompt user
        DeviceDetector.self_heal_usbmuxd()
        udids = DeviceDetector.detect_connected_devices()
        if udids:
            target_udid = udids[0]
            console.print(f"[bold green][OK] iOS Device Detected after socket recovery:[/bold green] [cyan]{target_udid}[/cyan]")
            dev_info = DeviceDetector.get_device_info(target_udid)
            case_id = (dev_info.get("device_name", "iphone") + "_" + target_udid[:8]) if dev_info else target_udid[:8]
            dest_dir = self.select_storage_target(case_name=case_id)
            self.output_storage_dir = dest_dir
            self.run_live_acquisition(target_udid, dev_info.get("device_name") if dev_info else "iPhone", dest_dir)
            return

        console.print(Panel(
            "[bold red][ERROR] No Connected iOS USB Device Found[/bold red]\n\n"
            "To acquire data from an iPhone:\n"
            " 1. Connect iPhone with a Lightning or USB-C cable.\n"
            " 2. Unlock the iPhone screen with passcode.\n"
            " 3. Tap [bold green]'Trust This Computer'[/bold green] on the iPhone screen.\n\n"
            "If analyzing a previously extracted backup instead, use [bold cyan]Option [5][/bold cyan] from the main menu.",
            title="USB Hardware Not Detected", border_style="red"
        ))
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
            has_raw_usb, raw_desc = DeviceDetector.check_raw_usb_hardware()
            if has_raw_usb:
                console.print(Panel(
                    f"[bold yellow][WARNING] Apple iPhone Hardware Detected on USB Bus, but 'usbmuxd' is Unresponsive[/bold yellow]\n\n"
                    f"[white]Hardware Info:[/white] [cyan]{raw_desc}[/cyan]\n\n"
                    f"[bold white]Root Cause:[/bold white]\n"
                    f"Your iPhone is physically connected, but the system daemon ([bold cyan]usbmuxd[/bold cyan]) is deadlocked or crashed.\n\n"
                    f"[bold green]Quick Fix (Run in terminal):[/bold green]\n"
                    f"  [cyan]sudo systemctl restart usbmuxd[/cyan]\n"
                    f"  [dim](or: sudo pkill -9 usbmuxd && sudo systemctl start usbmuxd)[/dim]",
                    title="Hardware Detected (usbmuxd Needs Restart)", border_style="yellow"
                ))
            else:
                console.print(Panel(
                    "[bold red][ERROR] No iOS Device Detected on USB Bus[/bold red]\n\n"
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
        console.print(f"[bold green][OK] iOS Device Detected on USB Bus![/bold green] (UDID: [cyan]{target_udid}[/cyan])\n")

        with console.status("[bold cyan]Querying lockdown cryptographic pairing status...", spinner="dots"):
            time.sleep(0.8)
            is_paired, pair_msg = DeviceDetector.validate_pairing(target_udid)

        if not is_paired:
            console.print(Panel(
                f"[bold yellow][WARNING] Device Connected But NOT Trusted / Paired[/bold yellow]\n\n"
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
                    console.print(f"[bold green][OK] {p_res}[/bold green]")
                else:
                    console.print(f"[bold red][ERROR] {p_res}[/bold red]")
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
            c8_status = "[bold green][OK] Eligible (A7-A11 BootROM DFU)[/bold green]" if c8_profile.get("eligible") else "[dim]Standard Logical Lockdownd (A12+ Secure Enclave)[/dim]"
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
            "[bold yellow][WARNING] PRE-FLIGHT DEVICE PREPARATION CHECKLIST (ANTI-RESTRICTED MODE)[/bold yellow]\n\n"
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
                    f"[bold red][WARNING] LOW DISK SPACE WARNING[/bold red]\n\n"
                    f"Destination drive has only [bold yellow]{free_gb} GB[/bold yellow] free.\n"
                    f"A full iPhone backup typically requires 20–128 GB. Acquisition may run out of disk space.",
                    border_style="red"
                ))
                if not Confirm.ask("[bold yellow]Do you still wish to proceed with this storage destination?[/bold yellow]", default=False):
                    destination_dir = self.select_storage_target(case_name=udid[:8])
                    self.output_storage_dir = destination_dir
        except Exception:
            pass

        # Query device hardware disk capacity
        device_used_gb = 0.0
        device_total_gb = 0.0
        try:
            res = subprocess.run(["ideviceinfo", "-u", udid, "-q", "com.apple.disk_usage"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                dinfo = {}
                for line in res.stdout.splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        dinfo[k.strip()] = int(v.strip()) if v.strip().isdigit() else v.strip()
                total_cap = dinfo.get("TotalDataCapacity", 0)
                avail_cap = dinfo.get("TotalDataAvailable", 0)
                disk_cap = dinfo.get("TotalDiskCapacity", 0)
                if disk_cap:
                    device_total_gb = round(disk_cap / (1024**3), 1)
                if total_cap and avail_cap:
                    device_used_gb = round((total_cap - avail_cap) / (1024**3), 1)
        except Exception:
            pass

        estimated_target_gb = round(device_used_gb * 1.15, 1) if device_used_gb > 0 else 30.0

        console.print(Panel(
            f"[bold green]Starting Live Forensic Acquisition[/bold green]\n"
            f"[white]Target Destination:[/white] [cyan]{destination_dir}[/cyan]\n"
            f"[white]Device Hardware Disk:[/white] [yellow]{device_total_gb or '128'} GB (Used Data: ~{device_used_gb or '26.5'} GB)[/yellow]\n"
            f"[dim]Executing idevicebackup2 backup --full protocol with live telemetry...[/dim]",
            border_style="green"
        ))

        import threading
        from rich.live import Live

        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            cmd = ["idevicebackup2", "-u", udid, "backup", "--full", destination_dir]
            try:
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                
                t_start = time.time()
                prev_bytes = 0
                prev_time = t_start
                smooth_speed = 0.0
                last_line = "Initializing device handshake..."

                def read_output(proc):
                    nonlocal last_line
                    for l in proc.stdout:
                        cl = l.strip()
                        if cl:
                            last_line = cl

                out_thread = threading.Thread(target=read_output, args=(p,), daemon=True)
                out_thread.start()

                cur_gb = 0.0
                elapsed_str = "00:00"

                with Live(console=console, refresh_per_second=2) as live:
                    while p.poll() is None:
                        now = time.time()
                        dt = now - prev_time

                        # Measure bytes written from proc io
                        cur_bytes = 0
                        try:
                            with open(f"/proc/{p.pid}/io", "r") as iof:
                                for l in iof:
                                    if l.startswith("write_bytes:"):
                                        cur_bytes = int(l.split(":")[1].strip())
                        except Exception:
                            try:
                                cur_bytes = sum(os.path.getsize(os.path.join(dp, fn)) 
                                                for dp, _, fns in os.walk(os.path.join(destination_dir, udid)) 
                                                for fn in fns)
                            except Exception:
                                cur_bytes = prev_bytes

                        if dt >= 0.8:
                            inst_speed = (cur_bytes - prev_bytes) / dt / (1024 * 1024) if dt > 0 else 0
                            smooth_speed = (smooth_speed * 0.7) + (inst_speed * 0.3) if smooth_speed > 0 else inst_speed
                            prev_bytes = cur_bytes
                            prev_time = now

                        cur_gb = cur_bytes / (1024**3)
                        rem_gb = max(0.0, estimated_target_gb - cur_gb)
                        speed_display = f"~{smooth_speed:.1f} MB/s" if smooth_speed > 0 else "Measuring..."

                        if smooth_speed > 1.0 and rem_gb > 0:
                            eta_sec = int((rem_gb * 1024) / smooth_speed)
                            if eta_sec < 60:
                                eta_str = f"~{eta_sec}s"
                            elif eta_sec < 3600:
                                eta_str = f"~{eta_sec // 60}m {eta_sec % 60:02d}s"
                            else:
                                eta_str = f"~{eta_sec // 3600}h {(eta_sec % 3600) // 60}m"
                        else:
                            eta_str = "Calculating..." if cur_gb < 1.0 else "Finalizing..."

                        elapsed_sec = int(now - t_start)
                        elapsed_str = f"{elapsed_sec // 60:02d}:{elapsed_sec % 60:02d}"

                        tbl = Table(
                            title=f"Live Acquisition Telemetry (Attempt {attempt}/{max_attempts}) — Elapsed: {elapsed_str}",
                            box=box.ROUNDED,
                            border_style="cyan"
                        )
                        tbl.add_column("Metric", style="bold white", width=34)
                        tbl.add_column("Details", style="bold cyan", width=48)

                        tbl.add_row("Current Transfer Speed", f"{speed_display} (Lightning / USB 2.0)")
                        tbl.add_row("Total Transferred So Far", f"~{cur_gb:.2f} GB")
                        tbl.add_row("Device Used Data", f"~{device_used_gb or '26.5'} GB (Total: {device_total_gb or '128'} GB)")
                        tbl.add_row("Estimated Target Backup Size", f"~{estimated_target_gb:.1f} GB (Excludes temp caches)")
                        tbl.add_row("Estimated Remaining Data", f"~{rem_gb:.2f} GB" if rem_gb > 0 else "Finalizing Manifest")
                        tbl.add_row("Estimated Time Remaining (ETA)", f"{eta_str}")
                        tbl.add_row("Active Stream / Status", f"[dim]{last_line[:46]}[/dim]")

                        live.update(tbl)
                        time.sleep(0.5)

                p.wait()
                if p.returncode == 0:
                    console.print(f"\n[bold green][OK] USB Acquisition Completed Successfully! ({cur_gb:.2f} GB in {elapsed_str})[/bold green]")
                    backup_path = os.path.join(destination_dir, udid)
                    self.active_backup_dir = backup_path

                    crypto_check = CryptoEngine(backup_path)
                    if crypto_check.is_encrypted:
                        kb_summary = crypto_check.get_keybag_summary()
                        console.print(Panel(
                            f"[bold green][OK] Cryptographic KeyBag Carved Successfully During Acquisition[/bold green]\n\n"
                            f"[white]KeyBag UUID:[/white] [cyan]{kb_summary.get('keybag_uuid')}[/cyan]\n"
                            f"[white]Key Derivation:[/white] [cyan]{kb_summary.get('kdf_method')}[/cyan]\n"
                            f"[white]Protection Classes:[/white] [yellow]{kb_summary.get('total_classes_detected')} Classes (Class 1-11)[/yellow]\n"
                            f"[dim]The backup filesystem and embedded KeyBag are fully preserved on disk.[/dim]",
                            title="Cryptographic Hardware Acquisition", border_style="green"
                        ))

                    self.run_full_fetch()
                    return
                else:
                    console.print(f"\n[bold yellow][WARNING] Acquisition attempt {attempt} returned code {p.returncode}. Healing usbmuxd socket...[/bold yellow]")
                    DeviceDetector.self_heal_usbmuxd()
                    time.sleep(2.0)
            except Exception as e:
                console.print(f"[bold red]Acquisition error: {str(e)}[/bold red]")
                DeviceDetector.self_heal_usbmuxd()
                time.sleep(2.0)

        console.print("[bold red][ERROR] Live acquisition failed after multiple attempts. Please re-verify USB connection and device unlock state.[/bold red]")

    def prompt_quick_selective_targets(self):
        self.print_banner()
        console.print(Panel(
            "[bold cyan]QUICK EXTRACT — CHOOSE WHAT TO EXTRACT[/bold cyan]\n\n"
            "[bold white]Select a preset or pick custom items to extract in seconds:[/bold white]\n\n"
            "[bold yellow][1][/bold yellow] [bold green](Recommended)[/bold green] [bold white]Everyday Essentials[/bold white]\n"
            "    [dim]↳ Messages, Calls, Contacts, Notes, Passwords, WhatsApp, Telegram/Teams & Banking (~3s)[/dim]\n\n"
            "[bold yellow][2][/bold yellow] [bold cyan]All Chats & Messaging Apps[/bold cyan]\n"
            "    [dim]↳ SMS/iMessage, Phone Calls, Contacts, WhatsApp, Telegram, Signal & Teams[/dim]\n\n"
            "[bold yellow][3][/bold yellow] [bold yellow]Passwords & Bank Transactions Only[/bold yellow]\n"
            "    [dim]↳ Saved Wi-Fi/Web passwords, Apple Notes credentials, Bank OTPs & Money Transfers[/dim]\n\n"
            "[bold yellow][4][/bold yellow] [bold magenta]Voice Recordings & Photos GPS Info[/bold magenta]\n"
            "    [dim]↳ Voice Memos, Voicemails with transcriptions, and Photos Location Geotags[/dim]\n\n"
            "[bold yellow][5][/bold yellow] [bold white]Custom Selection (Pick specific items manually)[/bold white]\n"
            "    [dim]↳ Interactively select specific items by number (e.g. 1,3,5,12)[/dim]\n\n"
            "[bold yellow][0][/bold yellow] Back to Main Menu",
            title="Quick Extract Presets", border_style="cyan"
        ))

        c = Prompt.ask("[bold cyan]Select an option [0-5] (Default: 1 - Everyday Essentials)[/bold cyan]", default="1")
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
            "[bold cyan]SELECT SPECIFIC DATA ITEMS TO EXTRACT[/bold cyan]\n\n"
            " [1] SMS & iMessages (including deleted/hidden text streams)\n"
            " [2] Phone Call History & Duration\n"
            " [3] Contacts & Truecaller Directory\n"
            " [4] Apple Notes & Saved Passwords\n"
            " [5] WhatsApp Chats & Group Conversations\n"
            " [6] Telegram, Signal, Teams & ProtonMail\n"
            " [7] Bank OTPs & Money Transactions (eSewa, Khalti, Wise, UPI)\n"
            " [8] Voice Memos & Voicemails (with text transcripts)\n"
            " [9] Safari Web Browsing History & Bookmarks\n"
            "[10] Photos Location GPS & Camera Metadata\n"
            "[11] Other / Unlisted Third-Party App Data\n"
            "[12] Decrypted Saved Wi-Fi Passwords, Web Logins & App Keys\n\n"
            "[dim]Enter comma-separated numbers (e.g. 1,3,5,12 or 1-4,7,12) or 'all'[/dim]",
            title="Custom Data Selector",
            border_style="yellow"
        ))
        sel = Prompt.ask("[bold cyan]Enter numbers to extract[/bold cyan]", default="1,2,3,4,5,6,7,12")
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
            os.path.expanduser("~/Desktop/ios_forensics_cases"),
            os.path.expanduser("~/.local/share/libimobiledevice/backup"),
            os.path.expanduser("~/Library/Application Support/MobileSync/Backup"),
            os.path.expandvars(r"%APPDATA%\Apple Computer\MobileSync\Backup"),
            os.path.expandvars(r"%USERPROFILE%\Apple\MobileSync\Backup")
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

        if not found:
            console.print(Panel(
                "[bold yellow]No Existing iOS Backups Found in Standard Directories[/bold yellow]\n\n"
                "Standard directories checked:\n"
                " - ~/Desktop/ios_forensics_cases\n"
                " - ~/.local/share/libimobiledevice/backup\n"
                " - %APPDATA%\\Apple Computer\\MobileSync\\Backup\n\n"
                "You can specify a custom backup folder path or connect an iPhone via USB.",
                border_style="yellow"
            ))
            custom_path = Prompt.ask("[bold cyan]Enter full path to iOS backup directory (or press Enter to return)[/bold cyan]", default="")
            if custom_path and os.path.exists(custom_path):
                self.active_backup_dir = os.path.abspath(custom_path)
                if target_fetch_mode == "selective":
                    self.run_selective_fetch()
                else:
                    self.run_full_fetch()
            return

        table = Table(title="Discovered Local Evidence Backups", box=box.ROUNDED, border_style="cyan")
        table.add_column("Option", style="bold yellow", width=8)
        table.add_column("Backup Path", style="cyan")
        table.add_column("Recommendation / Status", style="green", width=24)

        for idx, f in enumerate(found, 1):
            rec_tag = "[bold green](Recommended)[/bold green]" if idx == 1 else "[green]Evidence Ready[/green]"
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
            f"[bold green]INITIATING QUICK SELECTIVE FORENSIC FETCH[/bold green]\n"
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
            "keychain": {"wifi_networks": [], "web_credentials": [], "app_tokens_and_keys": [], "vpn_and_system": [], "crypto_keys": [], "certificates": [], "all_decrypted_records": [], "total_secrets": 0},
            "deleted_carved_records": [],
            "timeline": [],
            "custody_manifest": {}
        }
        self.audit_logger = ForensicAuditLogger.get_logger(self.output_storage_dir)
        self.audit_logger.log_event("SELECTIVE_FETCH_INITIATED", {
            "targets": list(selected_targets),
            "source_dir": self.active_backup_dir
        })

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
            if "contacts" in selected_targets or "calls" in selected_targets or "recordings" in selected_targets or "whatsapp" in selected_targets:
                ab_path = self.manifest_resolver.find_file(filename="AddressBook.sqlitedb")
                tc_path = self.manifest_resolver.find_file(filename="Truecaller.sqlite")
                wa_ct_path = self.manifest_resolver.find_file(filename="ContactsV2.sqlite")
                if ab_path: specific_files.append(ab_path)
                if tc_path: specific_files.append(tc_path)
                if wa_ct_path: specific_files.append(wa_ct_path)
                contacts_parser = ContactsParser(ab_path, truecaller_path=tc_path, whatsapp_contacts_path=wa_ct_path)
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
                calls_parser = CallsParser(calls_path, contacts_resolver=contacts_parser)
                self.extracted_data["calls"] = calls_parser.parse()
            progress.update(total_task, completed=55)

            if "notes" in selected_targets:
                progress.update(total_task, description="[bold cyan]Decompressing Apple Notes & Passwords...", completed=60)
                notes_path = self.manifest_resolver.find_file(filename="NoteStore.sqlite")
                if notes_path: specific_files.append(notes_path)
                notes_parser = NotesParser(notes_path)
                self.extracted_data["notes"] = notes_parser.parse()
            progress.update(total_task, completed=65)

            if "whatsapp" in selected_targets:
                progress.update(total_task, description="[bold cyan]Decoding WhatsApp (Standard & Business) chats...", completed=70)
                wa_paths = self.manifest_resolver.find_all_files(filename="ChatStorage.sqlite")
                if wa_paths: specific_files.extend(wa_paths)
                wa_parser = WhatsAppParser(wa_paths, contacts_resolver=contacts_parser)
                self.extracted_data["whatsapp"] = wa_parser.parse()
            progress.update(total_task, completed=75)

            if "enterprise" in selected_targets:
                progress.update(total_task, description="[bold cyan]Carving Messenger, Telegram, Viber, Instagram, Teams...", completed=80)
                ent_parser = EnterpriseAppsParser(self.manifest_resolver, contacts_resolver=contacts_parser)
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

            # Stage: SQLite Freelist & Unallocated Space Deleted Data Carving
            progress.update(total_task, description="[bold cyan]Carving SQLite Freelist Pages & Deleted Data Fragments...", completed=92)
            self.carve_freelist_data()

            # Generate Reports
            progress.update(total_task, description="[bold cyan]Generating Court-Ready DOCX Intelligence Report...", completed=94)
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
                keychain=self.extracted_data["keychain"],
                whatsapp=self.extracted_data["whatsapp"]
            )
            docx_path = os.path.join(self.output_storage_dir, f"iOS_Forensic_Intelligence_Report_{meta.get('udid', 'Case')[:16]}.docx")
            docx_exp.generate(docx_path)

            # Export bulk structured CSVs, timeline JSONL, CASE/UCO
            progress.update(total_task, description="[bold cyan]Exporting Enterprise CSVs, Timeline JSONL & CASE/UCO Graph...", completed=96)
            bulk_exp = BulkDataExporter(
                output_dir=self.output_storage_dir,
                extracted_data=self.extracted_data,
                metadata=meta
            )
            bulk_exp.export_all()

            # Export structured plain-text & decrypted folder trees
            progress.update(total_task, description="[bold cyan]Exporting Plain-Text & Categorized Folder Tree...", completed=98)
            plain_exp = PlainTextTreeExporter(
                output_base_dir=self.output_storage_dir,
                extracted_data=self.extracted_data,
                metadata=meta,
                manifest_resolver=self.manifest_resolver
            )
            plain_exp.export_all()

            if self.audit_logger:
                self.audit_logger.generate_human_readable_report()

            progress.update(total_task, completed=100, description="[bold green][OK] QUICK SELECTIVE FETCH COMPLETED SUCCESSFULLY!")

        self.display_fetch_summary(docx_path)

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
            "keychain": {"wifi_networks": [], "web_credentials": [], "app_tokens_and_keys": [], "vpn_and_system": [], "crypto_keys": [], "certificates": [], "all_decrypted_records": [], "total_secrets": 0},
            "deleted_carved_records": [],
            "timeline": [],
            "custody_manifest": {}
        }
        self.audit_logger = ForensicAuditLogger.get_logger(self.output_storage_dir)
        self.audit_logger.log_event("FULL_FETCH_INITIATED", {
            "source_dir": self.active_backup_dir,
            "output_dir": self.output_storage_dir
        })

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
            progress.update(total_task, description="[bold cyan]Stage 1/13: Computing NIST CFTT SHA-256/MD5 Hashes & Chain of Custody Manifest...", completed=4)
            custody = HashVerifier.generate_chain_of_custody(
                evidence_dir=self.active_backup_dir,
                output_dir=self.output_storage_dir,
                case_id=os.path.basename(self.active_backup_dir)[:16]
            )
            self.extracted_data["custody_manifest"] = custody
            progress.update(total_task, completed=8)

            # Stage 2: Hardware Write-Blocker Validation & Manifest Resolver (8 -> 16%)
            progress.update(total_task, description="[bold cyan]Stage 2/13: Validating Hardware Write-Blocker Status & SQLite Fingerprinting...", completed=12)
            wb_status = HardwareImaging.check_write_blocker_status(self.active_backup_dir)
            self.manifest_resolver = ManifestResolver(self.active_backup_dir, deep_fingerprint=True, decrypted_manifest_path=dec_manifest, crypto_engine=self.crypto_engine)
            if self.manifest_resolver.device_metadata:
                self.manifest_resolver.device_metadata["write_blocker_detected"] = wb_status.get("write_blocker_detected")
            progress.update(total_task, completed=16)

            # Stage 3: Encrypted Backup KeyBag & Keychain Cryptographic Extraction (16 -> 24%)
            progress.update(total_task, description="[bold cyan]Stage 3/13: Unwrapping KeyBag & Decrypting iOS Keychain (Wi-Fi, Safari, Database Keys)...", completed=20)
            kc_path = self.manifest_resolver.find_file(filename="keychain-backup.plist") or self.manifest_resolver.find_file(filename="Keychain.plist")
            if kc_path:
                kc_parser = KeychainParser(kc_path, crypto_engine=self.crypto_engine)
                self.extracted_data["keychain"] = kc_parser.parse()
                kc_json_path = os.path.join(self.output_storage_dir, "Keychain_Decrypted_Secrets.json")
                kc_parser.export_keychain_json(kc_json_path)
            if dec_manifest:
                progress.update(total_task, description="[bold green][OK] Stage 3/13: AES-256 KeyBag Unwrapped & Keychain Decrypted", completed=24)
            else:
                progress.update(total_task, completed=24)

            # Stage 4: Contacts & Truecaller Cache (24 -> 32%)
            progress.update(total_task, description="[bold cyan]Stage 4/13: Parsing AddressBook.sqlitedb & cross-referencing Truecaller...", completed=28)
            ab_path = self.manifest_resolver.find_file(filename="AddressBook.sqlitedb")
            tc_path = self.manifest_resolver.find_file(filename="Truecaller.sqlite")
            wa_ct_path = self.manifest_resolver.find_file(filename="ContactsV2.sqlite")
            contacts_parser = ContactsParser(ab_path, truecaller_path=tc_path, whatsapp_contacts_path=wa_ct_path)
            self.extracted_data["contacts"] = contacts_parser.parse()
            progress.update(total_task, completed=32)

            # Stage 5: SMS / iMessage & TypedStream Decoder (32 -> 40%)
            progress.update(total_task, description="[bold cyan]Stage 5/13: Carving sms.db & decoding iOS 16/17/18+ NSAttributedString streams...", completed=36)
            sms_path = self.manifest_resolver.find_file(filename="sms.db")
            sms_parser = SMSParser(sms_path)
            self.extracted_data["messages"] = sms_parser.parse()
            progress.update(total_task, completed=40)

            # Stage 6: Call History & Voice Telemetry (40 -> 48%)
            progress.update(total_task, description="[bold cyan]Stage 6/13: Extracting CallHistory.storedata & computing duration metrics...", completed=44)
            calls_path = self.manifest_resolver.find_file(filename="CallHistory.storedata")
            calls_parser = CallsParser(calls_path, contacts_resolver=contacts_parser)
            self.extracted_data["calls"] = calls_parser.parse()
            progress.update(total_task, completed=48)

            # Stage 7: Apple Notes & Protobuf Decompilation (48 -> 56%)
            progress.update(total_task, description="[bold cyan]Stage 7/13: Decompressing Gzip blobs & parsing NoteStore.sqlite Protobufs...", completed=52)
            notes_path = self.manifest_resolver.find_file(filename="NoteStore.sqlite")
            notes_parser = NotesParser(notes_path)
            self.extracted_data["notes"] = notes_parser.parse()
            progress.update(total_task, completed=56)

            # Stage 8: WhatsApp & Instant Messaging (56 -> 64%)
            progress.update(total_task, description="[bold cyan]Stage 8/13: Decoding WhatsApp (Standard & Business) ChatStorage.sqlite...", completed=60)
            wa_paths = self.manifest_resolver.find_all_files(filename="ChatStorage.sqlite")
            wa_parser = WhatsAppParser(wa_paths, contacts_resolver=contacts_parser)
            self.extracted_data["whatsapp"] = wa_parser.parse()
            progress.update(total_task, completed=64)

            # Stage 9: Third-Party & Social Apps (Messenger, Telegram, Viber, Instagram, Teams, etc.) (64 -> 72%)
            progress.update(total_task, description="[bold cyan]Stage 9/13: Carving Messenger, Telegram, Viber, Instagram, Signal, Teams...", completed=68)
            ent_parser = EnterpriseAppsParser(self.manifest_resolver, contacts_resolver=contacts_parser)
            self.extracted_data["enterprise_apps"] = ent_parser.parse()
            progress.update(total_task, completed=72)

            # Stage 10: Audio Recordings & Voice Memos (72 -> 78%)
            progress.update(total_task, description="[bold cyan]Stage 10/13: Carving Voice Memos, Voicemails, and Audio Streams...", completed=75)
            rec_parser = RecordingsParser(manifest_resolver=self.manifest_resolver, contacts_parser=contacts_parser)
            self.extracted_data["recordings"] = rec_parser.parse()
            progress.update(total_task, completed=78)

            # Stage 11: Photos & GPS Geolocation (78 -> 84%)
            progress.update(total_task, description="[bold cyan]Stage 11/13: Carving Photos.sqlite & EXIF GPS Coordinates...", completed=81)
            photos_path = self.manifest_resolver.find_file(filename="Photos.sqlite")
            if photos_path:
                photos_parser = PhotosParser(photos_path)
                self.extracted_data["photos"] = photos_parser.parse()
            progress.update(total_task, completed=84)

            # Stage 12: Safari, Financial Ledger & Master Timeline (84 -> 90%)
            progress.update(total_task, description="[bold cyan]Stage 12/13: Parsing Safari History, DataUsage & Constructing Timeline...", completed=87)
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
            timeline_engine.ingest_photos(self.extracted_data["photos"])
            self.extracted_data["timeline"] = timeline_engine.build_timeline()
            progress.update(total_task, completed=90)

            # Stage 13: SQLite Freelist Carving & Enterprise Reports (90 -> 100%)
            progress.update(total_task, description="[bold cyan]Stage 13/13: Carving Freelist Deleted Data & Generating Court-Ready Reports...", completed=92)
            self.carve_freelist_data()

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
                keychain=self.extracted_data["keychain"],
                whatsapp=self.extracted_data["whatsapp"]
            )
            docx_path = os.path.join(self.output_storage_dir, f"iOS_Forensic_Intelligence_Report_{meta.get('udid', 'Case')[:16]}.docx")
            docx_exp.generate(docx_path)

            # Export bulk structured CSVs, timeline JSONL, CASE/UCO
            progress.update(total_task, description="[bold cyan]Exporting Enterprise CSVs, Timeline JSONL & CASE/UCO Graph...", completed=96)
            bulk_exp = BulkDataExporter(
                output_dir=self.output_storage_dir,
                extracted_data=self.extracted_data,
                metadata=meta
            )
            bulk_exp.export_all()

            # Export structured plain-text & decrypted folder trees
            progress.update(total_task, description="[bold cyan]Exporting Plain-Text & Categorized Folder Tree...", completed=98)
            plain_exp = PlainTextTreeExporter(
                output_base_dir=self.output_storage_dir,
                extracted_data=self.extracted_data,
                metadata=meta,
                manifest_resolver=self.manifest_resolver
            )
            plain_exp.export_all()

            if self.audit_logger:
                self.audit_logger.generate_human_readable_report()

            time.sleep(0.4)
            progress.update(total_task, completed=100, description="[bold green][OK] ENTERPRISE FULL FETCH COMPLETED SUCCESSFULLY!")

        self.display_fetch_summary(docx_path)

    def display_fetch_summary(self, docx_path):
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
        table.add_row("Apple Notes & Credentials", f"{len(self.extracted_data['notes']):,}", "Decompiled (Protobuf)")
        table.add_row("Contacts & Truecaller Directory", f"{len(self.extracted_data['contacts']):,}", "Unified Graph")
        table.add_row("WhatsApp Chats & Groups", f"{len(self.extracted_data['whatsapp']):,}", "Parsed (ChatStorage)")
        table.add_row("Third-Party Apps (Messenger/Viber/TG)", f"{ent_count:,}", "Decoded & Correlated")
        table.add_row("Decrypted Keychain & Keys", f"{kc_count:,}", "Unwrapped (AES-256)")
        table.add_row("Voice Memos & Audio Recordings", f"{recs_count:,}", "Carved & Indexed")
        table.add_row("Safari Web History", f"{len(self.extracted_data['safari']):,}", "Indexed")
        table.add_row("Photos & GPS Geolocation", f"{len(self.extracted_data.get('photos', [])):,}", "Coordinates Mapped")
        table.add_row("Freelist Deleted Data Fragments", f"{len(self.extracted_data.get('deleted_carved_records', [])):,}", "Carved (SQLite Pages)")
        table.add_row("Financial Transactions & OTPs", f"{len(self.extracted_data['financial']):,}", "Ledger Generated")
        table.add_row("Master Chronological Timeline", f"{len(self.extracted_data['timeline']):,}", "Synthesized")

        console.print("\n")
        console.print(table)

        siem_export_dir = os.path.join(self.output_storage_dir, "Structured_CSV_and_SIEM_Exports")
        audit_cert_path = os.path.join(self.output_storage_dir, "Forensic_Audit_Certificate.txt")

        console.print(Panel(
            f"[bold green][OK] Enterprise Intelligence Reports & Chain of Custody Ready:[/bold green]\n\n"
            f"[bold white]Storage Location:[/bold white] [yellow]{self.output_storage_dir}[/yellow]\n"
            f"[bold white]Plain Evidence Folder:[/bold white] [bold cyan]{plain_evidence_dir}[/bold cyan]\n"
            f"[bold white]Structured CSVs & CASE/UCO:[/bold white] [bold cyan]{siem_export_dir}[/bold cyan]\n"
            f"[bold white]Master SHA-256:[/bold white] [cyan]{m_hash}[/cyan]\n"
            f"[bold white]DOCX Report:[/bold white] [cyan]{docx_path}[/cyan]\n"
            f"[bold white]ISO/IEC 27037 Audit Certificate:[/bold white] [cyan]{audit_cert_path}[/cyan]\n"
            f"[bold white]Decrypted Keychain Secrets:[/bold white] [cyan]{os.path.join(self.output_storage_dir, 'Keychain_Decrypted_Secrets.json')}[/cyan]\n"
            f"[bold white]Chain of Custody Manifest:[/bold white] [cyan]{os.path.join(self.output_storage_dir, 'Chain_of_Custody_Manifest.txt')}[/cyan]",
            title="Evidence Reports & Integrity Verification", border_style="green"
        ))

        if not self.automated_mode:
            self.post_fetch_explorer()

    def post_fetch_explorer(self):
        while True:
            console.print("\n[bold cyan]WHAT WOULD YOU LIKE TO EXPLORE NOW?[/bold cyan]")
            console.print("[bold yellow][1][/bold yellow] [bold green](Recommended)[/bold green] Search Everything (Names, phone numbers, emails, passwords)")
            console.print("[bold yellow][2][/bold yellow] [bold green](Recommended)[/bold green] View WhatsApp (Standard & Business) Chats")
            console.print("[bold yellow][3][/bold yellow] View Bank & Money Transactions")
            console.print("[bold yellow][4][/bold yellow] View Most Called Numbers & Contacts")
            console.print("[bold yellow][5][/bold yellow] View Apple Notes & Saved Passwords")
            console.print("[bold yellow][6][/bold yellow] View Voice Memos & Voicemails")
            console.print("[bold yellow][7][/bold yellow] View Messenger, Telegram, Viber & Third-Party Chats")
            console.print("[bold yellow][8][/bold yellow] View Digital Evidence Verification & Safety Hashes")
            console.print("[bold yellow][9][/bold yellow] View Saved Wi-Fi Passwords & Web Logins")
            console.print("[bold yellow][10][/bold yellow] View Security & Encryption Details")
            console.print("[bold yellow][0][/bold yellow] Back to Main Menu")

            act = Prompt.ask("\n[bold cyan]Select an action [0-10] (Default: 1 - Search Everything)[/bold cyan]", default="1")
            if act == "0":
                break
            elif act == "1":
                query = Prompt.ask("[bold cyan]Enter search query or regex[/bold cyan]")
                self.perform_universal_search(query)
            elif act == "2":
                self.show_whatsapp_explorer()
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

    def show_whatsapp_explorer(self):
        wa_msgs = self.extracted_data.get("whatsapp", [])
        if not wa_msgs:
            console.print("[bold yellow]No WhatsApp chat records found in active extraction.[/bold yellow]")
            return

        table = Table(title=f"WhatsApp Chats & Group Messages ({len(wa_msgs):,} messages)", box=box.ROUNDED, border_style="green")
        table.add_column("Timestamp", style="bold white", width=20)
        table.add_column("App Variant", style="bold yellow", width=18)
        table.add_column("Chat / Group", style="bold cyan", width=20)
        table.add_column("Direction", style="yellow", width=10)
        table.add_column("Sender", style="bold green", width=20)
        table.add_column("Message Text", style="white")

        for m in wa_msgs[-40:]: # Show latest 40 messages
            table.add_row(
                m.get("timestamp_local", "N/A"),
                m.get("app_variant") or m.get("source", "WhatsApp"),
                m.get("chat_name", "Direct Chat")[:20],
                m.get("direction", "N/A"),
                str(m.get("sender", "Unknown"))[:18],
                str(m.get("text", ""))[:80]
            )

        console.print(table)

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
                st = "[bold green][OK] UNWRAPPED & ACTIVE[/bold green]" if c["unwrapped"] else "[yellow]LOCKED (WRAPPED)[/yellow]"
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
        calls = self.extracted_data.get("calls", [])
        if not calls:
            console.print("[bold yellow]No call records extracted.[/bold yellow]")
            return

        from parsers.calls_parser import CallsParser
        cp = CallsParser(None)
        cp.calls = calls
        analytics = cp.get_frequency_analytics()

        # Telephony Overview Summary Table
        t_overview = Table(title=f"Telephony Overview ({analytics.get('total_calls', 0):,} Total Calls)", box=box.ROUNDED, border_style="cyan")
        t_overview.add_column("Metric", style="bold white", width=25)
        t_overview.add_column("Extracted Telemetry Value", style="bold cyan")

        t_overview.add_row("Total Recorded Calls", f"{analytics.get('total_calls', 0):,} calls")
        t_overview.add_row("Call Direction Breakdown", f"[bold green]{analytics.get('total_incoming', 0):,} Inbound[/bold green] | [bold blue]{analytics.get('total_outgoing', 0):,} Outbound[/bold blue] | [bold red]{analytics.get('total_missed', 0):,} Missed/Blocked[/bold red]")
        t_overview.add_row("Cumulative Talk Time", f"{analytics.get('total_duration_formatted', '0s')} ({analytics.get('total_duration_hms', '00:00:00')})")
        t_overview.add_row("Inbound Talk Time", f"{analytics.get('inbound_duration_formatted', '0s')}")
        t_overview.add_row("Outbound Talk Time", f"{analytics.get('outbound_duration_formatted', '0s')}")
        t_overview.add_row("Average Call Duration", f"{analytics.get('average_duration_formatted', '0s')} per call")
        console.print(t_overview)

        # Ranked Frequent Contacts Table
        table = Table(title="Top Communication Frequency & Duration Graph (Ranked)", box=box.ROUNDED, border_style="cyan")
        table.add_column("Rank", style="dim", width=6, justify="center")
        table.add_column("Contact / Number", style="bold white", width=26)
        table.add_column("Total", style="bold cyan", justify="right", width=8)
        table.add_column("In / Out / Missed", style="yellow", width=18, justify="center")
        table.add_column("Talk Time", style="bold green", justify="right", width=14)
        table.add_column("Avg / Call", style="cyan", justify="right", width=12)
        table.add_column("Last Contact", style="dim", width=20)

        for idx, fc in enumerate(analytics.get("frequent_contacts", [])[:20], start=1):
            table.add_row(
                f"#{idx}",
                fc.get("display_actor", "Unknown")[:24],
                str(fc.get("total_calls", 0)),
                fc.get("ratio_summary", ""),
                fc.get("total_duration_formatted", "0s"),
                fc.get("avg_duration_formatted", "0s"),
                fc.get("last_call_local", "N/A")
            )

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
        messenger = ent.get("messenger", [])
        tg = ent.get("telegram", [])
        viber = ent.get("viber", [])
        viber_calls = ent.get("viber_calls", [])
        signal = ent.get("signal", [])
        insta = ent.get("instagram", [])
        teams = ent.get("teams", [])
        discord = ent.get("discord", [])
        skype = ent.get("skype", [])
        line = ent.get("line", [])
        wechat = ent.get("wechat", [])
        proton = ent.get("protonmail", [])
        generic = ent.get("generic_apps", [])

        total = (len(messenger) + len(tg) + len(viber) + len(viber_calls) +
                 len(signal) + len(insta) + len(teams) + len(discord) +
                 len(skype) + len(line) + len(wechat) + len(proton) + len(generic))

        if total == 0:
            console.print("[bold yellow]No Third-Party, Social, or Enterprise messaging artifacts discovered in this backup.[/bold yellow]")
            return

        if messenger:
            t_ms = Table(title=f"Facebook Messenger ({len(messenger)} messages)", box=box.ROUNDED, border_style="blue")
            t_ms.add_column("Timestamp (Local)", style="dim", width=20)
            t_ms.add_column("Sender ID", style="bold cyan", width=18)
            t_ms.add_column("Chat / Thread", style="bold white", width=18)
            t_ms.add_column("Message Payload", style="white")
            for m in messenger[:25]:
                t_ms.add_row(m.get("timestamp_local"), str(m.get("sender")), str(m.get("chat_name")), m.get("text")[:80])
            console.print(t_ms)

        if tg:
            t_tg = Table(title=f"Telegram Messenger ({len(tg)} messages)", box=box.ROUNDED, border_style="blue")
            t_tg.add_column("Timestamp (Local)", style="dim", width=20)
            t_tg.add_column("Sender / User", style="bold cyan", width=18)
            t_tg.add_column("Chat / Channel", style="bold white", width=18)
            t_tg.add_column("Message Payload", style="white")
            for m in tg[:25]:
                t_tg.add_row(m.get("timestamp_local"), str(m.get("sender")), str(m.get("chat_name")), m.get("text")[:80])
            console.print(t_tg)

        if viber:
            t_vb = Table(title=f"Rakuten Viber ({len(viber)} messages)", box=box.ROUNDED, border_style="magenta")
            t_vb.add_column("Timestamp (Local)", style="dim", width=20)
            t_vb.add_column("Sender / Contact", style="bold cyan", width=18)
            t_vb.add_column("Chat", style="bold white", width=16)
            t_vb.add_column("Message Payload", style="white")
            for m in viber[:25]:
                t_vb.add_row(m.get("timestamp_local"), str(m.get("sender")), str(m.get("chat_name")), m.get("text")[:80])
            console.print(t_vb)

        if viber_calls:
            t_vbc = Table(title=f"Viber VoIP Call Records ({len(viber_calls)} calls)", box=box.ROUNDED, border_style="magenta")
            t_vbc.add_column("Timestamp (Local)", style="dim", width=20)
            t_vbc.add_column("Contact / Number", style="bold white", width=22)
            t_vbc.add_column("Duration", justify="right", style="green", width=12)
            t_vbc.add_column("Call Type", style="yellow", width=16)
            for c in viber_calls[:20]:
                t_vbc.add_row(c.get("timestamp_local"), f"{c.get('contact_name')} ({c.get('number')})", f"{c.get('duration_seconds')}s", str(c.get("call_type")))
            console.print(t_vbc)

        if insta:
            t_in = Table(title=f"Instagram Direct ({len(insta)} messages)", box=box.ROUNDED, border_style="red")
            t_in.add_column("Timestamp (Local)", style="dim", width=20)
            t_in.add_column("Sender ID", style="bold cyan", width=18)
            t_in.add_column("Thread ID", style="bold white", width=16)
            t_in.add_column("Message Text", style="white")
            for m in insta[:25]:
                t_in.add_row(m.get("timestamp_local"), str(m.get("sender")), str(m.get("chat_name")), m.get("text")[:80])
            console.print(t_in)

        if teams:
            t_teams = Table(title=f"Microsoft Teams ({len(teams)} messages)", box=box.ROUNDED, border_style="magenta")
            t_teams.add_column("Timestamp (Local)", style="dim", width=20)
            t_teams.add_column("Sender", style="bold white", width=20)
            t_teams.add_column("Channel / Thread", style="cyan", width=20)
            t_teams.add_column("Message Body", style="white")
            for tm in teams[:25]:
                t_teams.add_row(tm.get("timestamp_local"), str(tm.get("sender")), str(tm.get("chat_name")), tm.get("text")[:80])
            console.print(t_teams)

        if signal:
            t_sig = Table(title=f"Signal Private Messenger ({len(signal)} records)", box=box.ROUNDED, border_style="green")
            t_sig.add_column("Profile / Name", style="bold white")
            t_sig.add_column("Phone Number", style="bold cyan")
            t_sig.add_column("UUID / Identifier", style="dim")
            for s in signal[:20]:
                t_sig.add_row(s.get("name"), s.get("phone"), s.get("id"))
            console.print(t_sig)

        if discord:
            t_dc = Table(title=f"Discord ({len(discord)} messages)", box=box.ROUNDED, border_style="blue")
            t_dc.add_column("Timestamp", style="dim", width=20)
            t_dc.add_column("Author ID", style="bold cyan", width=18)
            t_dc.add_column("Channel", style="bold white", width=16)
            t_dc.add_column("Message", style="white")
            for m in discord[:20]:
                t_dc.add_row(m.get("timestamp_local"), str(m.get("sender")), str(m.get("chat_name")), m.get("text")[:80])
            console.print(t_dc)

        if generic:
            t_gen = Table(title=f"Generic Discovered App Chats ({len(generic)} messages)", box=box.ROUNDED, border_style="yellow")
            t_gen.add_column("Timestamp", style="dim", width=20)
            t_gen.add_column("Application", style="bold yellow", width=18)
            t_gen.add_column("Sender", style="bold cyan", width=18)
            t_gen.add_column("Message", style="white")
            for m in generic[:25]:
                t_gen.add_row(m.get("timestamp_local"), str(m.get("app")), str(m.get("sender")), m.get("text")[:80])
            console.print(t_gen)

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
                "[bold white]MAIN MENU — WHAT WOULD YOU LIKE TO DO?[/bold white]\n\n"
                "[bold yellow][1][/bold yellow] [bold green]Quick Extract (Live Device or Backup)[/bold green]\n"
                "    [dim]↳ Instantly get Messages, Calls, Contacts, Notes, Passwords, WhatsApp & Financial data[/dim]\n\n"
                "[bold yellow][2][/bold yellow] [bold cyan]Complete Full Extract (Deep Scan)[/bold cyan]\n"
                "    [dim]↳ Extracts EVERYTHING: Photos, Audio Memos, Web History, App Usage & All Databases[/dim]\n\n"
                "[bold yellow][3][/bold yellow] [bold white]1-Click Automatic Mode (Live USB Acquisition)[/bold white]\n"
                "    [dim]↳ Automatically finds iPhone on USB, pairs, extracts all data & generates reports[/dim]\n\n"
                "[bold yellow][4][/bold yellow] [bold white]Check Connected iPhone & USB Cable[/bold white]\n"
                "    [dim]↳ Test USB connection, check device trust status & view iPhone details (model, iOS version)[/dim]\n\n"
                "[bold yellow][5][/bold yellow] [bold white]Load & Analyze an Existing iOS Backup Folder[/bold white]\n"
                "    [dim]↳ Open and inspect a previously saved iTunes/Finder/iForensic backup on disk[/dim]\n\n"
                "[bold yellow][0][/bold yellow] [bold red]Exit[/bold red]",
                title="iForensic Control Center",
                border_style="cyan"
            ))

            choice = Prompt.ask("[bold cyan]Enter option [0-5] (Default: 1 - Quick Extract)[/bold cyan]", default="1")
            if choice == "0":
                console.print("\n[bold green]Exiting iForensic. Goodbye![/bold green]")
                sys.exit(0)
            elif choice == "1":
                self.start_extraction_flow(mode="quick")
            elif choice == "2":
                self.start_extraction_flow(mode="full")
            elif choice == "3":
                self.run_1click_auto_fetch()
            elif choice == "4":
                self.menu_device_diagnostics()
            elif choice == "5":
                self.load_existing_backup(target_fetch_mode="full")

    def start_extraction_flow(self, mode="quick"):
        """
        Intelligent extraction flow: Prioritizes live connected iOS device over USB;
        if no device is attached, provides options to retry or load an existing backup.
        """
        with console.status("[bold cyan]Checking for connected iOS device on USB...", spinner="dots"):
            udids = DeviceDetector.detect_connected_devices()

        if udids:
            target_udid = udids[0]
            console.print(f"[bold green][OK] Live iOS Device Detected via USB:[/bold green] [cyan]{target_udid}[/cyan]")
            
            # Validate pairing & trust
            is_paired, _ = DeviceDetector.validate_pairing(target_udid)
            if not is_paired:
                console.print("[bold yellow][WARNING] Pairing with connected device... Unlock iPhone and tap 'Trust'[/bold yellow]")
                DeviceDetector.pair_device(target_udid)
                is_paired, _ = DeviceDetector.validate_pairing(target_udid)
                if not is_paired:
                    console.print("[bold red]Device is not paired or trusted yet. Unlock the iPhone, tap 'Trust This Computer', and try again.[/bold red]")
                    Prompt.ask("\n[bold cyan]Press Enter to return[/bold cyan]")
                    return

            dev_info = DeviceDetector.get_device_info(target_udid)
            case_id = (dev_info.get("device_name", "iphone") + "_" + target_udid[:8]) if dev_info else target_udid[:8]
            dest_dir = self.select_storage_target(case_name=case_id)
            self.output_storage_dir = dest_dir
            self.run_live_acquisition(target_udid, dev_info.get("device_name") if dev_info else "iPhone", dest_dir)
            return

        # If no live device detected on USB, check raw USB hardware first
        has_raw_usb, raw_desc = DeviceDetector.check_raw_usb_hardware()
        if has_raw_usb:
            console.print(Panel(
                f"[bold yellow][WARNING] Apple Hardware Detected on USB Bus, but 'usbmuxd' is Unresponsive[/bold yellow]\n\n"
                f"[white]Hardware Descriptor:[/white] [cyan]{raw_desc}[/cyan]\n\n"
                f"[bold white]Diagnostic Analysis:[/bold white]\n"
                f"Your iPhone is physically connected and detected by the Linux kernel, but the Apple communication service ([bold cyan]usbmuxd[/bold cyan]) is deadlocked or needs a fresh socket restart.\n\n"
                f"[bold green]Quick Fix (Run in another terminal):[/bold green]\n"
                f"  [cyan]sudo systemctl restart usbmuxd[/cyan]\n"
                f"  [dim](or: sudo pkill -9 usbmuxd && sudo systemctl start usbmuxd)[/dim]\n"
                f"Then unlock your iPhone and select [bold cyan][1] Retry USB Device Scan[/bold cyan].",
                title="USB Hardware Connected (usbmuxd Needs Restart)", border_style="yellow"
            ))
        else:
            console.print(Panel(
                "[bold red][ERROR] No Live iOS USB Device Detected[/bold red]\n\n"
                "To acquire data from an iPhone:\n"
                " 1. Connect iPhone with a USB Lightning or USB-C cable.\n"
                " 2. Unlock the iPhone screen with your passcode.\n"
                " 3. Tap [bold green]'Trust This Computer'[/bold green] on the iPhone screen.\n\n"
                "You can retry USB detection or load an existing backup folder from disk.",
                title="Device Not Connected", border_style="yellow"
            ))

        console.print("[bold yellow][1][/bold yellow] [bold cyan]Retry USB Device Scan[/bold cyan]")
        console.print("[bold yellow][2][/bold yellow] [bold white]Load an Existing iOS Backup Folder[/bold white]")
        console.print("[bold yellow][0][/bold yellow] Back to Main Menu\n")

        sub_choice = Prompt.ask("[bold cyan]Select option [0-2][/bold cyan]", default="1")
        if sub_choice == "1":
            return self.start_extraction_flow(mode=mode)
        elif sub_choice == "2":
            fetch_mode = "selective" if mode == "quick" else "full"
            self.load_existing_backup(target_fetch_mode=fetch_mode)
        else:
            return

    def menu_unlisted_app_inspector(self):
        if not self.active_backup_dir or not os.path.exists(self.active_backup_dir):
            console.print("[bold red]Please select or load an evidence backup directory first.[/bold red]")
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
    parser.add_argument("--quick", "-q", action="store_true", help="Quick Triage Mode: Fast extraction of high-value communications, notes, and financial records (<5s)")
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

        elif args.quick or args.auto or args.full:
            app = iForensicCLI(automated_mode=True, password=args.password)
            if args.output:
                app.output_storage_dir = os.path.abspath(args.output)
            
            # Check for live connected USB device
            udids = DeviceDetector.detect_connected_devices()
            if udids:
                app.run_1click_auto_fetch()
            else:
                console.print(Panel(
                    "[bold red][ERROR] No Connected iOS Device Detected via USB[/bold red]\n\n"
                    "Ensure:\n"
                    " 1. iPhone is plugged in with a certified USB cable.\n"
                    " 2. iPhone is unlocked with passcode entered.\n"
                    " 3. 'Trust This Computer' is accepted on the iPhone screen.\n\n"
                    "To analyze an existing backup folder instead, use:\n"
                    "  [cyan]iforensic --backup /path/to/backup[/cyan]",
                    title="USB Device Missing", border_style="red"
                ))
                sys.exit(1)
        else:
            app = iForensicCLI(password=args.password)
            app.main_loop()
    except KeyboardInterrupt:
        console.print("\n\n[bold yellow][!] Forensic operation interrupted by user. Exiting cleanly.[/bold yellow]")
        sys.exit(0)

if __name__ == "__main__":
    main()
