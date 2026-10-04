# iForensic — Next-Gen iOS Digital Forensics Suite 🔍📱

[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blue.svg)](https://github.com)
[![Python](https://img.shields.io/badge/Python-3.8%2B-brightgreen.svg)](https://python.org)
[![Forensics](https://img.shields.io/badge/Forensic%20Standard-Court%20%26%20Disclosure%20Ready-purple.svg)](https://github.com)

**iForensic** is an enterprise-grade, cross-platform interactive CLI suite for iOS digital forensic acquisition, deep binary carving, multi-artifact entity correlation, and automated intelligence report generation.

---

## ⚡ Key Capabilities

* **1-Command Autonomous Pipeline:** Auto-detects USB hardware, pairs, carves all artifacts, and generates reports in a single command (`iforensic --auto`).
* **Cross-Platform Compatibility:** Runs seamlessly on **Linux**, **macOS**, and **Windows**.
* **Live USB Acquisition Wizard:** Step-by-step pairing validation (`idevicepair`), lockdown trust checks, and hardware telemetry.
* **Storage Target Selection:** Internal NVMe/SSD or auto-detection and auto-mounting of external USB hard drives and flash drives.
* **Automated Startup Maintenance & Self-Updater:** Automatically checks upstream git repositories for updates, auto-heals `usbmuxd` sockets, and purges orphaned staging files on every tool launch.
* **Unlisted App & SQLite Schema Inspector:** Includes interactive ad-hoc schema discovery and heuristic chat carving across ANY unlisted third-party application database.
* **NIST CFTT Cryptographic Hash Verification:** Automatically computes streaming SHA-256 and MD5 hashes across all source evidence files and produces court-ready `Chain_of_Custody_Manifest.txt` and `Chain_of_Custody_Verification.json`.
* **Encrypted Backup Decryption Engine:** Derives master keys via PBKDF2/scrypt, unwraps Protection Class Keys (RFC 3394), and decrypts `Manifest.db` on the fly when passphrase is provided.
* **Hardware Write-Blocker & Checkm8 Profiler:** Validates OS/hardware read-only mount flags (`ro,noatime`) and evaluates BootROM physical imaging readiness for A7–A11 chipsets.
* **Enterprise Cloud & Secure App Decoders:** Carves cached databases for **Telegram** (`tgdata.db`), **Signal** (`signal.sqlite`), **Microsoft Teams** (`teams.db`), and **ProtonMail**.
* **Modern iOS TypedStream Carving:** Decodes iOS 16/17/18+ binary `NSAttributedString` (`attributedBody`) in `sms.db`.
* **Gzip & Protobuf Notes Decompiler:** Unpacks Apple Notes (`NoteStore.sqlite`) binary streams, credentials, and deleted fragments.
* **Contacts & Identity Resolution:** Carves `AddressBook.sqlitedb` (first/last names, phone numbers, emails, jobs, notes) and unifies with Truecaller caches.
* **Audio Recordings & Voice Memos:** Decodes Apple Voice Memos (`Recordings.sqlite` / `CloudRecordings.db`), Voicemails with transcriptions (`voicemail.db`), WhatsApp voice notes, and indexes raw audio streams (`.m4a`, `.opus`, `.aac`, `.wav`, `.amr`, `.mp3`).
* **Multi-Database Entity Resolution:** Unifies Contacts, Calls, SMS, WhatsApp, and Truecaller into a single identity graph.
* **Automated Financial Ledger:** Scans SMS and notes for Bank OTPs, transactions, Wise, eSewa, Khalti, and UPI transfers.
* **Multi-Format Reporting:** Generates executive **DOCX** reports and standalone **Interactive HTML Dashboards**.

---

## 💻 Installation (Any OS)

### 1. Install Python Package
Clone the repository and install globally using `pip`:

```bash
cd iforensic
pip install .
```

*Or install in editable mode for active development:*
```bash
pip install -e .
```

---

## 🔧 Prerequisites (By Operating System)

### 🐧 Linux (Debian / Ubuntu / Kali / Arch)
```bash
sudo apt update
sudo apt install libimobiledevice6 libimobiledevice-utils usbmuxd
```

### 🍎 macOS (Homebrew)
```bash
brew install libimobiledevice usbmuxd
```

### 🪟 Windows 10 / 11 (Command Prompt / PowerShell / Windows Terminal)
1. Install **Python 3.8+** (from [python.org](https://www.python.org) or Microsoft Store — ensure *"Add python.exe to PATH"* is checked).
2. Install [iTunes for Windows](https://www.apple.com/itunes/) (provides Apple USB Mobile Device drivers).
3. *(Optional for live USB backup on Windows)* Download and add [libimobiledevice-win64](https://github.com/libimobiledevice-win32/imobiledevice-net/releases) to your `PATH`.
4. Run directly in **PowerShell**, **Command Prompt (CMD)**, or **Windows Terminal**:
   ```cmd
   pip install -e .
   iforensic --auto
   ```
   *(Or run directly via module: `python -m iforensic` / `python cli.py`)*

---

## 🚀 Usage & Execution Modes

### ⚡ Mode 1: Quick Selective Triage Fetch (Fastest — < 3 Seconds)
Instantly parses high-value tactical intelligence (SMS, Calls, Contacts, Apple Notes, WhatsApp, Telegram/Teams, Financial Ledgers) with ultra-fast database hashing:

```bash
iforensic --quick
```
*(Shortcut: `iforensic -q`)*

---

### 🎯 Mode 2: Targeted Module Extraction (`--targets` / `-t`)
Extracts only the specific forensic artifacts requested by the investigator:

```bash
# Extract only financial transactions and Apple Notes passwords:
iforensic --backup /path/to/backup --targets notes,financial

# Extract all communications & decrypted keychain secrets:
iforensic -b /path/to/backup -t messages,calls,contacts,whatsapp,enterprise,keychain
```
*Available Target Modules:* `messages`, `calls`, `contacts`, `notes`, `whatsapp`, `enterprise`, `financial`, `recordings`, `safari`, `photos`, `unlisted`, `keychain`.

---

### 🔑 Hardware AES-256 Decryption & Cryptographic Keychain Extraction
When analyzing encrypted iOS backups (AES-256), `iForensic` automatically derives master keys and decrypts both database files and device cryptographic keys:

* **Key Derivation (PBKDF2 / scrypt):** Derives master keys via DPIC/DPSL multi-pass KDF (iOS 10.2 - 18+).
* **RFC 3394 Class Key Unwrapping:** Unwraps Protection Classes 1 through 11.
* **On-The-Fly Database Decryption:** Transparently decrypts `Manifest.db`, `sms.db`, `CallHistory.storedata`, `NoteStore.sqlite`, `ChatStorage.sqlite`, etc., into staging for instant downstream analysis.
* **Keychain Decryption (`keychain-backup.plist` / `Keychain.plist`):**
  * **Wi-Fi Passwords & Networks:** SSIDs, BSSIDs, and WPA2/WPA3 passphrases.
  * **Web & Cloud Logins:** Saved Safari credentials, usernames, passwords, and corporate portals.
  * **App Database Encryption Keys:** Decrypts application-specific database keys (e.g., **Signal** `OWSPrimaryStorageCipherKey` SQLCipher master key, WhatsApp tokens, OAuth refresh secrets).
  * **Hardware & System Keys:** AES-256 symmetric keys, RSA/ECDSA private keys, and certificates.
  * **Export:** Generates structured `Keychain_Decrypted_Secrets.json` and renders tables in DOCX/HTML reports.

---

### 🔬 Mode 3: 100% Full Deep Forensic Acquisition (Court Standard)
Executes comprehensive bitstream verification with parallel multi-core NIST CFTT hashing across all files in evidence, deep audio carving, photos EXIF GPS, and zero-day unlisted database carving:

```bash
iforensic --auto
# or
iforensic --full --backup /path/to/backup/
```
*(With custom output: `iforensic -b /path/to/backup/ -o /media/user/ExternalDrive/`)*

---

### 🎮 Mode 4: Interactive Guided Wizard (Default)
Launch the interactive terminal console with interactive preset selectors and checkboxes:

```bash
iforensic
```

#### Interactive Main Menu:
* **Option `[1]` (Recommended for Rapid Triage):** ⚡ **Quick Selective Fetch** (Pick Presets or Custom Checkboxes — runs in < 3s).
* **Option `[2]` (Recommended for Complete Evidence):** 🔬 **100% Full Deep Forensic Acquisition & Full Carve**.
* **Option `[3]`:** 1-Click Autonomous Auto-Fetch (Detect USB / Local Evidence).
* **Option `[4]`:** Live USB Hardware Diagnostics & Lockdown Pairing Wizard.
* **Option `[5]`:** Ingest Existing iOS Backup / Evidence Directory.
* **Option `[6]`:** Universal Entity Search & Multi-Database Grep.
* **Option `[7]`:** View System Environment & Storage Diagnostics.
* **Option `[8]`:** Unlisted Application & Ad-Hoc SQLite Schema Inspector.
* **Option `[9]`:** Autonomous Troubleshooter & Self-Healing Diagnostics.
* **Option `[0]`:** Exit Forensic Suite.

---

## 🪟 Windows Terminal & CLI Guide

`iForensic` is built with first-class Windows terminal support. It runs natively in **Windows Terminal**, **PowerShell**, **Command Prompt (`cmd.exe`)**, and **WSL 2**.

### 🛠️ Windows Installation & Execution

```powershell
# 1. Clone repository and navigate inside
cd C:\path\to\iforensic

# 2. Install requirements and package in editable mode
pip install -e .

# 3. Launch 1-Click Auto Mode
iforensic --auto

# Or launch the interactive console
iforensic
```
*(Alternative execution methods without PATH configuration: `python -m iforensic` or `python cli.py`)*

### 📁 Common Windows iOS Backup Directories
Windows automatically archives iTunes / Apple Devices backups into the following locations:
* **Standard iTunes (EXE / Installer):**
  ```cmd
  %APPDATA%\Apple Computer\MobileSync\Backup\
  # Expanded: C:\Users\<Username>\AppData\Roaming\Apple Computer\MobileSync\Backup\<UDID>
  ```
* **Microsoft Store iTunes / Apple Devices App:**
  ```cmd
  %USERPROFILE%\Apple\MobileSync\Backup\
  # Expanded: C:\Users\<Username>\Apple\MobileSync\Backup\<UDID>
  ```

### ⚡ Windows Command-Line Examples:
```cmd
:: 1-Click Auto Run
iforensic --auto

:: Parse a specific Windows iTunes backup folder to an external drive (e.g. D:\ or E:\)
iforensic --backup "%APPDATA%\Apple Computer\MobileSync\Backup\00008110-00184DC63CD3801E" --output "D:\Forensic_Cases\Case_01"

:: Ingest directly with short flags
iforensic -b "C:\Forensics\iPhone_Backup" -o "E:\Case_Reports"
```

---

## 🛡️ Field Acquisition & Anti-Restricted Mode Protocol

To prevent **USB Restricted Mode** disconnection or device brownouts during large acquisitions:

1. **Auto-Brightness:** Go to `Settings > Accessibility > Display & Text Size` → Turn **OFF Auto-Brightness** and set brightness to minimum (prevents thermal throttling & rapid battery depletion).
2. **Auto-Lock:** Go to `Settings > Display & Brightness` → Set **Auto-Lock to 'Never'** (keeps interface alive and prevents USB port disconnect).
3. **Lockdown Trust:** Keep screen unlocked with passcode entered and confirm **'Trust This Computer'**.
4. **Battery & Power:** Ensure the device is >50% charged or connected through a powered USB hub.

---

## 📄 Output Artifacts & Reports

* **DOCX Report:** `iOS_Forensic_Intelligence_Report_<UDID>.docx` (Court-ready executive styling)
* **HTML Dashboard:** `Interactive_Forensic_Dashboard.html` (Single-file offline dashboard with instant search, tabs, and analytics)
* **Chain of Custody:** `Chain_of_Custody_Manifest.txt` & `Chain_of_Custody_Verification.json` (NIST CFTT cryptographic hash records)

---

## 🔒 Forensic Soundness & Integrity
All database operations utilize read-only (`mode=ro`) RFC 8089 URI connections across Windows, macOS, and Linux, ensuring source evidence files are never modified.

---

## 🆘 Autonomous Troubleshooting & Emergency Support

`iForensic` includes a 2-tier autonomous self-healing troubleshooter:
1. **Tier 1 (Automated Self-Repair):** Automatically restarts stalled `usbmuxd` multiplexer daemons, clears deadlocked sockets, and purges orphaned file handles.
2. **Tier 2 (Forensic Crash Dump & Developer Escalation):** If an unrecoverable hardware or OS limitation occurs, `iForensic` captures a full forensic telemetry dump (`forensic_incident_dump_*.json`) and prompts emergency escalation to the lead developer:
   * **Lead Developer Email:** `ANUDITKHATRI2011@GMAIL.COM`

