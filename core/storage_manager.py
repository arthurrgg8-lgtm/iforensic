import os
import shutil
import subprocess
import json
import platform
import string

class StorageManager:
    """
    Cross-platform storage manager supporting Linux, macOS, and Windows.
    Auto-detects mounted or unmounted external USB drives, hard disks, and removable media.
    """

    @staticmethod
    def get_os_type():
        return platform.system().lower()  # 'linux', 'darwin', 'windows'

    @staticmethod
    def list_external_storage():
        """
        Discovers external and secondary storage devices across Linux, macOS, and Windows.
        """
        os_type = StorageManager.get_os_type()
        if os_type == "windows":
            return StorageManager._list_storage_windows()
        elif os_type == "darwin":
            return StorageManager._list_storage_macos()
        else:
            return StorageManager._list_storage_linux()

    @staticmethod
    def _list_storage_windows():
        devices = []
        # Check standard Windows drive letters A: to Z:
        for letter in string.ascii_uppercase:
            drive_path = f"{letter}:\\"
            if os.path.exists(drive_path):
                try:
                    usage = shutil.disk_usage(drive_path)
                    is_system_drive = (letter == 'C')
                    label = f"Local Disk ({letter}:)" if is_system_drive else f"Removable/Drive ({letter}:)"
                    devices.append({
                        "name": f"{letter}:",
                        "label": label,
                        "path": drive_path,
                        "mountpoint": drive_path,
                        "fstype": "NTFS/FAT32",
                        "size_gb": round(usage.total / (1024**3), 2),
                        "free_gb": round(usage.free / (1024**3), 2),
                        "is_mounted": True,
                        "is_external": not is_system_drive
                    })
                except Exception:
                    pass
        return [d for d in devices if d.get("is_external")] or devices

    @staticmethod
    def _list_storage_macos():
        devices = []
        volumes_dir = "/Volumes"
        if os.path.exists(volumes_dir):
            try:
                for entry in os.listdir(volumes_dir):
                    full_p = os.path.join(volumes_dir, entry)
                    # Skip symlink to root or Macintosh HD
                    if os.path.islink(full_p) or entry in ["Macintosh HD", "Macintosh HD - Data"]:
                        continue
                    if os.path.isdir(full_p):
                        try:
                            usage = shutil.disk_usage(full_p)
                            devices.append({
                                "name": entry,
                                "label": f"External Volume ({entry})",
                                "path": full_p,
                                "mountpoint": full_p,
                                "fstype": "APFS/HFS+/exFAT",
                                "size_gb": round(usage.total / (1024**3), 2),
                                "free_gb": round(usage.free / (1024**3), 2),
                                "is_mounted": True
                            })
                        except Exception:
                            pass
            except Exception:
                pass
        return devices

    @staticmethod
    def _list_storage_linux():
        devices = []
        # 1. Inspect block devices via lsblk JSON
        try:
            res = subprocess.run(
                ["lsblk", "-J", "-b", "-o", "NAME,PATH,SIZE,TYPE,FSTYPE,LABEL,MOUNTPOINT,RM,HOTPLUG,TRAN,MODEL,VENDOR"],
                capture_output=True, text=True, timeout=5
            )
            if res.returncode == 0:
                data = json.loads(res.stdout)
                for block in data.get("blockdevices", []):
                    is_external = block.get("rm") or block.get("hotplug") or block.get("tran") == "usb"
                    StorageManager._process_linux_block_device(block, is_external, devices)
        except Exception:
            pass

        # 2. Check standard user mount locations (/media or /run/media or /mnt)
        user = os.environ.get("USER", "")
        media_dirs = [f"/media/{user}", f"/run/media/{user}", "/mnt", "/media"] if user else ["/media", "/mnt"]
        for m_dir in media_dirs:
            if os.path.exists(m_dir):
                try:
                    for entry in os.listdir(m_dir):
                        full_p = os.path.join(m_dir, entry)
                        if os.path.isdir(full_p) and os.path.ismount(full_p):
                            if not any(d.get("mountpoint") == full_p for d in devices):
                                try:
                                    usage = shutil.disk_usage(full_p)
                                    devices.append({
                                        "name": entry,
                                        "label": entry,
                                        "path": full_p,
                                        "mountpoint": full_p,
                                        "fstype": "Mounted Volume",
                                        "size_gb": round(usage.total / (1024**3), 2),
                                        "free_gb": round(usage.free / (1024**3), 2),
                                        "is_mounted": True
                                    })
                                except Exception:
                                    pass
                except Exception:
                    pass

        return devices

    @staticmethod
    def _process_linux_block_device(block, is_external_parent, devices_list):
        is_ext = is_external_parent or block.get("rm") or block.get("hotplug") or block.get("tran") == "usb"
        mount = block.get("mountpoint")
        size_b = block.get("size") or 0
        size_gb = round(size_b / (1024**3), 2)

        if "children" in block:
            for child in block["children"]:
                StorageManager._process_linux_block_device(child, is_ext, devices_list)
        elif is_ext and block.get("type") in ["part", "disk"]:
            free_gb = 0.0
            if mount and os.path.exists(mount):
                try:
                    free_gb = round(shutil.disk_usage(mount).free / (1024**3), 2)
                except Exception:
                    pass

            label = block.get("label") or block.get("name") or "External Drive"
            model = block.get("model") or block.get("vendor") or ""
            display_name = f"{label} ({model})".strip() if model else label

            devices_list.append({
                "name": block.get("name"),
                "label": display_name,
                "path": block.get("path"),
                "mountpoint": mount,
                "fstype": block.get("fstype") or "unknown",
                "size_gb": size_gb,
                "free_gb": free_gb,
                "is_mounted": bool(mount)
            })

    @staticmethod
    def mount_device_if_needed(device_entry):
        """
        Mounts an unmounted partition across supported operating systems.
        """
        if device_entry.get("is_mounted") and device_entry.get("mountpoint"):
            return True, device_entry["mountpoint"]

        os_type = StorageManager.get_os_type()
        dev_path = device_entry.get("path")
        if not dev_path:
            return False, "Invalid device path"

        if os_type == "windows":
            # On Windows, drive letters are automatically assigned
            return True, dev_path

        elif os_type == "darwin":
            try:
                subprocess.run(["diskutil", "mount", dev_path], capture_output=True, text=True, timeout=10)
                # Re-scan to find mount point
                for d in StorageManager._list_storage_macos():
                    if d.get("path") == dev_path and d.get("mountpoint"):
                        return True, d["mountpoint"]
                return True, "/Volumes"
            except Exception as e:
                return False, str(e)

        else: # Linux
            try:
                res = subprocess.run(["udisksctl", "mount", "-b", dev_path], capture_output=True, text=True, timeout=10)
                out = res.stdout + res.stderr
                if res.returncode == 0 or "Mounted" in out:
                    parts = out.strip().split(" at ")
                    if len(parts) > 1:
                        return True, parts[1].rstrip(".")
                    for e in StorageManager._list_storage_linux():
                        if e.get("path") == dev_path and e.get("mountpoint"):
                            return True, e["mountpoint"]
                    return True, "/media"
                else:
                    return False, f"Mount failed: {out.strip()}"
            except Exception as e:
                return False, str(e)
