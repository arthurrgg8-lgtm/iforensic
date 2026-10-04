import subprocess
import shutil
import os
import time
import platform

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
    def self_heal_usbmuxd():
        """
        Self-healing routine: If usbmuxd daemon is hanging, stalled, or unresponsive,
        automatically attempts restart and socket re-initialization.
        """
        os_type = DeviceDetector.get_os_type()
        try:
            if os_type == "linux":
                subprocess.run(["sudo", "-n", "systemctl", "restart", "usbmuxd"], capture_output=True, timeout=5)
                # If sudo without password fails, attempt user socket restart or direct usbmuxd trigger
                subprocess.run(["usbmuxd", "-u", "-f"], capture_output=True, timeout=2)
            elif os_type == "darwin":
                subprocess.run(["brew", "services", "restart", "usbmuxd"], capture_output=True, timeout=5)
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
            res = subprocess.run(["idevice_id", "-l"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                udids = [line.strip() for line in res.stdout.strip().splitlines() if line.strip()]
                if udids:
                    return udids
        except Exception:
            pass

        # Self-healing attempt if no device found initially
        if auto_heal:
            DeviceDetector.self_heal_usbmuxd()
            try:
                res = subprocess.run(["idevice_id", "-l"], capture_output=True, text=True, timeout=5)
                if res.returncode == 0:
                    return [line.strip() for line in res.stdout.strip().splitlines() if line.strip()]
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
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
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

            cmd = ["idevicepair"]
            if udid:
                cmd.extend(["-u", udid])
            cmd.append("pair")

            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                out = (res.stdout + res.stderr).lower()
                if "success" in out or "paired" in out:
                    return True, "Successfully established cryptographic pairing trust!"
            except Exception:
                pass
            time.sleep(1.5)

        return False, "Please ensure the iPhone is unlocked and tap 'Trust' on the screen."

    @staticmethod
    def pair_device(udid=None):
        return DeviceDetector.auto_pair_with_retries(udid)

    @staticmethod
    def get_device_info(udid=None):
        if not DeviceDetector.is_tool_available("ideviceinfo"):
            return None

        cmd = ["ideviceinfo"]
        if udid:
            cmd.extend(["-u", udid])

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if res.returncode != 0:
                # Retry once after usbmuxd ping
                DeviceDetector.self_heal_usbmuxd()
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if res.returncode != 0:
                    return None

            info = {}
            for line in res.stdout.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    info[k.strip()] = v.strip()

            summary = {
                "udid": info.get("UniqueDeviceID", udid or "Unknown"),
                "device_name": info.get("DeviceName", "Unknown iPhone"),
                "product_type": info.get("ProductType", "Unknown"),
                "product_version": info.get("ProductVersion", "Unknown"),
                "build_version": info.get("BuildVersion", "Unknown"),
                "serial_number": info.get("SerialNumber", "Unknown"),
                "model_number": info.get("ModelNumber", "Unknown"),
                "hardware_platform": info.get("HardwarePlatform", "Unknown"),
                "chip_id": info.get("ChipID", "Unknown"),
                "wi_fi_address": info.get("WiFiAddress", "Unknown"),
                "bluetooth_address": info.get("BluetoothAddress", "Unknown"),
                "baseband_version": info.get("BasebandVersion", "Unknown"),
                "time_zone": info.get("TimeZone", "Unknown"),
                "battery_level": f"{info.get('BatteryCurrentCapacity', 'N/A')}%",
                "is_charging": info.get("BatteryIsCharging", "Unknown"),
                "passcode_protected": info.get("PasswordProtected", "Unknown"),
                "raw_info": info
            }
            return summary
        except Exception:
            return None
