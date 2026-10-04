import os
import subprocess
import shutil
import platform
import re

class HardwareImaging:
    """
    Hardware Write-Blocker Verification & Physical Imaging Readiness Engine.
    Implements:
    1. Operating System & Hardware Write-Blocker validation (read-only mount verification)
    2. Apple Hardware Platform checkm8 / BootROM vulnerability profiling (A7 - A11 chipsets)
    3. DFU & Recovery Mode device state detection
    """

    CHECKM8_VULNERABLE_CHIPS = {
        "s5l8960x": "Apple A7 (iPhone 5s, iPad Air 1, iPad mini 2/3) - Fully Checkm8 Vulnerable",
        "t7000": "Apple A8 (iPhone 6/6 Plus, iPad mini 4, Apple TV 4) - Fully Checkm8 Vulnerable",
        "t7001": "Apple A8X (iPad Air 2) - Fully Checkm8 Vulnerable",
        "s8000": "Apple A9 (Samsung) (iPhone 6s/6s Plus, iPhone SE 1st Gen) - Fully Checkm8 Vulnerable",
        "s8003": "Apple A9 (TSMC) (iPhone 6s/6s Plus, iPhone SE 1st Gen) - Fully Checkm8 Vulnerable",
        "s8001": "Apple A9X (iPad Pro 9.7 / 12.9 1st Gen) - Fully Checkm8 Vulnerable",
        "t8010": "Apple A10 Fusion (iPhone 7/7 Plus, iPad 6th/7th Gen) - Fully Checkm8 Vulnerable",
        "t8011": "Apple A10X Fusion (iPad Pro 10.5 / 12.9 2nd Gen) - Fully Checkm8 Vulnerable",
        "t8015": "Apple A11 Bionic (iPhone 8/8 Plus, iPhone X) - Fully Checkm8 Vulnerable (SEP Mitigation on iOS 14+)"
    }

    CHECKM8_PRODUCT_TYPES = {
        "iPhone6,1": "iPhone 5s", "iPhone6,2": "iPhone 5s",
        "iPhone7,1": "iPhone 6 Plus", "iPhone7,2": "iPhone 6",
        "iPhone8,1": "iPhone 6s", "iPhone8,2": "iPhone 6s Plus", "iPhone8,4": "iPhone SE (1st Gen)",
        "iPhone9,1": "iPhone 7", "iPhone9,2": "iPhone 7 Plus", "iPhone9,3": "iPhone 7", "iPhone9,4": "iPhone 7 Plus",
        "iPhone10,1": "iPhone 8", "iPhone10,4": "iPhone 8", "iPhone10,2": "iPhone 8 Plus", "iPhone10,5": "iPhone 8 Plus",
        "iPhone10,3": "iPhone X", "iPhone10,6": "iPhone X"
    }

    @staticmethod
    def check_write_blocker_status(target_path):
        """
        Validates if the target evidence storage is operating under hardware or software write-protection.
        """
        target_path = os.path.abspath(target_path)
        os_name = platform.system().lower()

        status = {
            "path": target_path,
            "is_read_only": False,
            "mount_options": "N/A",
            "write_blocker_detected": False,
            "details": "Standard Read/Write Storage"
        }

        # 1. Linux Mount & Sysfs Check
        if os_name == "linux":
            try:
                # Check /proc/mounts
                with open("/proc/mounts", "r") as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            mount_point = parts[1]
                            opts = parts[3].split(",")
                            if target_path.startswith(mount_point):
                                status["mount_options"] = parts[3]
                                if "ro" in opts:
                                    status["is_read_only"] = True
                                    status["write_blocker_detected"] = True
                                    status["details"] = f"Mounted Read-Only (ro) at {mount_point} [Forensically Protected]"
                                break

                # Check block device ro flag if applicable
                dev_res = subprocess.run(["df", "--output=source", target_path], capture_output=True, text=True)
                lines = dev_res.stdout.strip().splitlines()
                if len(lines) > 1:
                    dev_node = lines[1].strip()
                    dev_base = os.path.basename(dev_node)
                    # Check /sys/block/*/ro
                    sys_ro_path = f"/sys/class/block/{dev_base}/ro"
                    if os.path.exists(sys_ro_path):
                        with open(sys_ro_path, "r") as ro_f:
                            if ro_f.read().strip() == "1":
                                status["is_read_only"] = True
                                status["write_blocker_detected"] = True
                                status["details"] = f"Hardware/Kernel Block Device Read-Only Flag Set (/sys/class/block/{dev_base}/ro=1)"
            except Exception:
                pass

        # 2. macOS diskutil Check
        elif os_name == "darwin":
            try:
                res = subprocess.run(["diskutil", "info", target_path], capture_output=True, text=True)
                if "Read-Only:" in res.stdout:
                    for line in res.stdout.splitlines():
                        if "Read-Only:" in line and "Yes" in line:
                            status["is_read_only"] = True
                            status["write_blocker_detected"] = True
                            status["details"] = "macOS Diskutil confirms Volume is Mounted Read-Only"
            except Exception:
                pass

        # 3. Active Probe Test (Non-destructive attempt to check write permission)
        if not status["is_read_only"]:
            try:
                test_file = os.path.join(target_path, ".iforensic_ro_probe.tmp")
                with open(test_file, "w") as f:
                    f.write("probe")
                os.remove(test_file)
                status["is_read_only"] = False
            except (IOError, OSError, PermissionError):
                status["is_read_only"] = True
                status["details"] = "Filesystem rejected write operation (Read-Only Mode active)"

        return status

    @staticmethod
    def evaluate_checkm8_compatibility(device_telemetry):
        """
        Evaluates physical BootROM / checkm8 exploit eligibility based on chipset & model.
        """
        if not device_telemetry:
            return {
                "eligible": False,
                "chip_id": "Unknown",
                "product_type": "Unknown",
                "status": "No device telemetry available for evaluation."
            }

        product_type = device_telemetry.get("product_type", "")
        hardware_platform = str(device_telemetry.get("hardware_platform", "")).lower()
        chip_id = str(device_telemetry.get("chip_id", "")).lower()

        is_eligible = False
        description = "Modern A12+ Bionic / M-Series (Not vulnerable to checkm8 BootROM exploit. Logical / Advanced Backup Extraction Standard)."

        for c_key, c_desc in HardwareImaging.CHECKM8_VULNERABLE_CHIPS.items():
            if c_key in hardware_platform or c_key in chip_id:
                is_eligible = True
                description = c_desc
                break

        if not is_eligible and product_type in HardwareImaging.CHECKM8_PRODUCT_TYPES:
            is_eligible = True
            model_name = HardwareImaging.CHECKM8_PRODUCT_TYPES[product_type]
            description = f"{model_name} ({product_type}) - Compatible with checkm8 BootROM DFU Physical Acquisition"

        return {
            "eligible": is_eligible,
            "product_type": product_type,
            "chip_id": chip_id or hardware_platform or "N/A",
            "description": description,
            "physical_acquisition_method": "checkm8 DFU RAMDisk / Full Bitstream Imaging" if is_eligible else "Advanced Logical Lockdown Extraction (iOS 15-18+ Standard)"
        }

    @staticmethod
    def detect_dfu_recovery_devices():
        """
        Detects iOS devices currently sitting in DFU Mode (05ac:1227) or Recovery Mode (05ac:1281).
        """
        devices = []
        os_name = platform.system().lower()

        if os_name == "linux" and shutil.which("lsusb"):
            try:
                res = subprocess.run(["lsusb"], capture_output=True, text=True, timeout=3)
                for line in res.stdout.splitlines():
                    if "05ac:1227" in line:
                        devices.append({"mode": "DFU Mode", "vendor_id": "05ac", "product_id": "1227", "status": "Ready for checkm8 payload injection"})
                    elif "05ac:1281" in line:
                        devices.append({"mode": "Recovery Mode", "vendor_id": "05ac", "product_id": "1281", "status": "Apple Recovery Interface Active"})
            except Exception:
                pass

        if shutil.which("irecovery"):
            try:
                res = subprocess.run(["irecovery", "-m"], capture_output=True, text=True, timeout=3)
                out = res.stdout.strip()
                if out:
                    devices.append({"mode": out, "source": "irecovery query", "status": "Interactive recovery interface accessible"})
            except Exception:
                pass

        return devices
