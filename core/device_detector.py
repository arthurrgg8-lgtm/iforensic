import subprocess
import shutil
import os
import time
import platform
import re

class DeviceDetector:
    """
    Cross-platform iOS USB hardware detection, lockdown pairing validator,
    and automated self-healing daemon manager.
    """

    @staticmethod
    def get_os_type():
        return platform.system().lower()

    @staticmethod
    def is_tool_available(tool_name):
        return shutil.which(tool_name) is not None

    @staticmethod
    def check_environment():
        tools = ["idevice_id", "ideviceinfo", "idevicepair", "idevicebackup2", "usbmuxd"]
        status = {}
        for tool in tools:
            status[tool] = shutil.which(tool) is not None
        return status

    @staticmethod
    def get_os_install_guide():
        os_type = DeviceDetector.get_os_type()
        if os_type == "darwin":
            return "macOS detected: Run 'brew install libimobiledevice usbmuxd'"
        elif os_type == "windows":
            return "Windows detected: Install iTunes and libimobiledevice-win64 binaries."
        else:
            return "Linux detected: Run 'sudo apt install libimobiledevice6 libimobiledevice-utils usbmuxd'"

    @staticmethod
    def check_raw_usb_hardware():
        """
        Directly queries the OS USB subsystem for Apple hardware (Vendor ID 05ac).
        Returns True if Apple hardware is physically connected, even if usbmuxd is deadlocked.
        """
        os_type = DeviceDetector.get_os_type()
        try:
            if os_type == "linux" and shutil.which("lsusb"):
                res = subprocess.run(["lsusb"], capture_output=True, text=True, timeout=3)
                if "05ac:" in res.stdout.lower() or "apple" in res.stdout.lower():
                    for line in res.stdout.splitlines():
                        if "05ac:" in line.lower() or "apple" in line.lower():
                            return True, line.strip()
                    return True, "Apple Device (Vendor 05ac)"
            elif os_type == "darwin":
                res = subprocess.run(["system_profiler", "SPUSBDataType"], capture_output=True, text=True, timeout=4)
                if "iphone" in res.stdout.lower() or "ipad" in res.stdout.lower() or "0x05ac" in res.stdout.lower():
                    return True, "Apple iOS Device (USB)"
        except Exception:
            pass
        return False, None

    @staticmethod
    def self_heal_usbmuxd():
        """
        Self-healing routine: If usbmuxd daemon is hanging, stalled, or unresponsive,
        automatically attempts restart and socket re-initialization.
        """
        os_type = DeviceDetector.get_os_type()
        try:
            if os_type == "linux":
                subprocess.run(["sudo", "-n", "systemctl", "restart", "usbmuxd"], capture_output=True, timeout=3)
                subprocess.run(["sudo", "-n", "pkill", "-9", "usbmuxd"], capture_output=True, timeout=2)
                subprocess.run(["usbmuxd", "-u", "-f"], capture_output=True, timeout=2)
            elif os_type == "darwin":
                subprocess.run(["brew", "services", "restart", "usbmuxd"], capture_output=True, timeout=4)
            time.sleep(1.0)
            return True
        except Exception:
            return False

    @staticmethod
    def detect_connected_devices(auto_heal=True):
        """
        Detects connected iOS devices with automated self-healing fallback.
        """
        if not DeviceDetector.is_tool_available("idevice_id"):
            return []

        try:
            res = subprocess.run(["idevice_id", "-l"], capture_output=True, text=True, timeout=4)
            if res.returncode == 0:
                udids = [line.strip() for line in res.stdout.strip().splitlines() if line.strip() and not line.startswith("ERROR")]
                if udids:
                    return udids
        except Exception:
            pass

        # Self-healing attempt if no device found initially
        if auto_heal:
            DeviceDetector.self_heal_usbmuxd()
            try:
                res = subprocess.run(["idevice_id", "-l"], capture_output=True, text=True, timeout=4)
                if res.returncode == 0:
                    udids = [line.strip() for line in res.stdout.strip().splitlines() if line.strip() and not line.startswith("ERROR")]
                    if udids:
                        return udids
            except Exception:
                pass

        return []

    @staticmethod
    def validate_pairing(udid=None):
        if not DeviceDetector.is_tool_available("idevicepair"):
            return False, f"idevicepair utility not found in PATH."

        cmd = ["idevicepair"]
        if udid:
            cmd.extend(["-u", udid])
        cmd.append("validate")

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=4)
            out = (res.stdout + res.stderr).lower()
            if "success" in out or "validated pairing" in out:
                return True, "Device is paired and trusted."
            elif "could not connect" in out:
                return False, "Device disconnected or USB multiplexer reset."
            elif "trust" in out or "passcode" in out or "not paired" in out:
                return False, "Device is locked or 'Trust This Computer' prompt has not been accepted."
            else:
                return False, res.stdout.strip() or res.stderr.strip()
        except Exception as e:
            return False, str(e)

    @staticmethod
    def auto_pair_with_retries(udid=None, max_retries=3):
        """
        Self-healing auto-pairing loop with retry handshake.
        """
        for attempt in range(1, max_retries + 1):
            is_valid, _ = DeviceDetector.validate_pairing(udid)
            if is_valid:
                return True, "Device successfully validated and trusted."
            
            # Attempt active pair request
            if DeviceDetector.is_tool_available("idevicepair"):
                pair_cmd = ["idevicepair"]
                if udid:
                    pair_cmd.extend(["-u", udid])
                pair_cmd.append("pair")
                try:
                    subprocess.run(pair_cmd, capture_output=True, text=True, timeout=4)
                except Exception:
                    pass
            time.sleep(1.0)

        return False, "Pairing timed out. Please ensure iPhone screen is unlocked and passcode is entered."

    @staticmethod
    def get_device_info(udid=None):
        """
        Queries lockdown service for deep device hardware telemetry and iOS version.
        """
        if not DeviceDetector.is_tool_available("ideviceinfo"):
            return None

        cmd = ["ideviceinfo"]
        if udid:
            cmd.extend(["-u", udid])

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode != 0:
                return None

            info = {}
            for line in res.stdout.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    info[k.strip()] = v.strip()

            return {
                "udid": info.get("UniqueDeviceID", udid or "Unknown"),
                "device_name": info.get("DeviceName", "iPhone"),
                "product_type": info.get("ProductType", "Unknown iPhone"),
                "product_version": info.get("ProductVersion", "Unknown iOS"),
                "build_version": info.get("BuildVersion", "Unknown Build"),
                "serial_number": info.get("SerialNumber", "Unknown Serial"),
                "model_number": info.get("ModelNumber", "Unknown Model"),
                "wifi_mac": info.get("WiFiAddress", "Unknown MAC"),
                "bluetooth_mac": info.get("BluetoothAddress", "Unknown Bluetooth"),
                "timezone": info.get("TimeZone", "UTC"),
                "battery_level": info.get("BatteryCurrentCapacity", "N/A"),
                "is_paired": True
            }
        except Exception:
            return None

    @staticmethod
    def pair_device(udid=None):
        if not DeviceDetector.is_tool_available("idevicepair"):
            return False, "idevicepair not available"
        cmd = ["idevicepair"]
        if udid:
            cmd.extend(["-u", udid])
        cmd.append("pair")
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return res.returncode == 0, res.stdout.strip() or res.stderr.strip()
        except Exception as e:
            return False, str(e)
