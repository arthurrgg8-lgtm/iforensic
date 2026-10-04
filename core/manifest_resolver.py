import os
import sqlite3
import plistlib
import hashlib

from core.db_utils import connect_readonly_sqlite

class ManifestResolver:
    """
    Parses iOS backup manifest files (Manifest.db, Manifest.plist, Info.plist, Status.plist).
    Implements:
    1. Manifest.db database querying
    2. Dynamic SHA-1 Domain calculations
    3. Deep SQLite Schema Fingerprinting (auto-discovers databases by table signatures)
    """

    KNOWN_DOMAIN_MAP = {
        "sms.db": ("HomeDomain", "Library/SMS/sms.db"),
        "CallHistory.storedata": ("HomeDomain", "Library/CallHistoryDB/CallHistory.storedata"),
        "AddressBook.sqlitedb": ("HomeDomain", "Library/AddressBook/AddressBook.sqlitedb"),
        "AddressBookImages.sqlitedb": ("HomeDomain", "Library/AddressBook/AddressBookImages.sqlitedb"),
        "NoteStore.sqlite": ("AppDomainGroup-group.com.apple.notes", "NoteStore.sqlite"),
        "SafariHistory.db": ("HomeDomain", "Library/Safari/History.db"),
        "Photos.sqlite": ("CameraRollDomain", "Media/PhotoData/Photos.sqlite"),
        "DataUsage.sqlite": ("WirelessDomain", "Library/Databases/DataUsage.sqlite"),
        "ChatStorage.sqlite": ("AppDomainGroup-group.net.whatsapp.WhatsApp.shared", "ChatStorage.sqlite"),
        "Truecaller.sqlite": ("AppDomain-com.truesoftware.TrueCaller", "Library/Application Support/db.sqlite"),
        "CloudRecordings.db": ("AppDomainGroup-group.com.apple.VoiceMemos.shared", "Recordings/CloudRecordings.db"),
        "Recordings.sqlite": ("MediaDomain", "Media/Recordings/Recordings.sqlite"),
        "voicemail.db": ("HomeDomain", "Library/Voicemail/voicemail.db"),
        "tgdata.db": ("AppDomain-ph.telegra.Telegraph", "Documents/tgdata.db"),
        "signal.sqlite": ("AppDomainGroup-group.org.whispersystems.signal", "Documents/signal.sqlite"),
        "teams.db": ("AppDomain-com.microsoft.skype.teams", "Library/Application Support/teams.db"),
        "protonmail.db": ("AppDomain-ch.protonmail.protonmail", "Documents/protonmail.db")
    }

    SCHEMA_SIGNATURES = {
        "sms.db": ["message", "handle", "chat"],
        "CallHistory.storedata": ["ZCALLRECORD"],
        "AddressBook.sqlitedb": ["ABPerson", "ABMultiValue"],
        "NoteStore.sqlite": ["ZICCLOUDSYNCINGOBJECT", "ZICNOTEDATA"],
        "SafariHistory.db": ["history_items", "history_visits"],
        "Photos.sqlite": ["ZGENERICASSET"],
        "DataUsage.sqlite": ["zprocess", "zliveusage"],
        "ChatStorage.sqlite": ["ZWAMESSAGE", "ZWACHATSESSION"],
        "Truecaller.sqlite": ["ZCONTACT"],
        "CloudRecordings.db": ["ZCLOUDRECORDING"],
        "Recordings.sqlite": ["ZRECORDING"],
        "voicemail.db": ["voicemail"],
        "tgdata.db": ["messages_v2"],
        "signal.sqlite": ["recipient"],
        "teams.db": ["chat_messages"],
        "protonmail.db": ["messages"]
    }

    def __init__(self, backup_dir):
        self.backup_dir = os.path.abspath(backup_dir)
        self.snapshot_dir = os.path.join(self.backup_dir, "Snapshot") if os.path.exists(os.path.join(self.backup_dir, "Snapshot")) else self.backup_dir

        self.manifest_db_path = self._find_first(["Manifest.db", "Snapshot/Manifest.db"])
        self.info_plist_path = self._find_first(["Info.plist", "Snapshot/Info.plist"])
        self.manifest_plist_path = self._find_first(["Manifest.plist", "Snapshot/Manifest.plist"])
        self.status_plist_path = self._find_first(["Status.plist", "Snapshot/Status.plist"])

        self.is_valid_backup = False
        self.is_encrypted = False
        self.device_metadata = {}
        self.file_map = {}   # { (domain, relative_path): real_disk_path }
        self.hash_map = {}   # { file_id: real_disk_path }
        self.fingerprinted_dbs = {} # { artifact_name: real_disk_path }

        self._load_metadata()
        self._index_manifest_db()
        self._index_known_hashes()
        self._fingerprint_sqlite_databases()

    def _find_first(self, relative_candidates):
        for c in relative_candidates:
            p = os.path.join(self.backup_dir, c)
            if os.path.exists(p):
                return p
        return None

    def _load_metadata(self):
        if self.info_plist_path and os.path.exists(self.info_plist_path):
            try:
                with open(self.info_plist_path, "rb") as f:
                    info = plistlib.load(f)
                    self.device_metadata["device_name"] = info.get("Device Name", "Unknown")
                    self.device_metadata["display_name"] = info.get("Display Name", "iPhone")
                    self.device_metadata["phone_number"] = info.get("Phone Number", "N/A")
                    self.device_metadata["product_type"] = info.get("Product Type", "iPhone")
                    self.device_metadata["product_version"] = info.get("Product Version", "iOS")
                    self.device_metadata["build_version"] = info.get("Build Version", "Unknown")
                    self.device_metadata["serial_number"] = info.get("Serial Number", "Unknown")
                    self.device_metadata["udid"] = info.get("Unique Identifier", "Unknown")
                    self.device_metadata["last_backup_date"] = str(info.get("Last Backup Date", "N/A"))
                    self.is_valid_backup = True
            except Exception:
                pass

        if self.manifest_plist_path and os.path.exists(self.manifest_plist_path):
            try:
                with open(self.manifest_plist_path, "rb") as f:
                    mani = plistlib.load(f)
                    self.is_encrypted = mani.get("IsEncrypted", False)
                    self.device_metadata["is_encrypted"] = self.is_encrypted
                    self.is_valid_backup = True
            except Exception:
                pass

    def _index_manifest_db(self):
        if not self.manifest_db_path or not os.path.exists(self.manifest_db_path):
            return

        try:
            conn = connect_readonly_sqlite(self.manifest_db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT fileID, domain, relativePath FROM Files")
            for file_id, domain, rel_path in cursor.fetchall():
                real_path = self._locate_hash_file(file_id)
                if real_path:
                    self.file_map[(domain, rel_path)] = real_path
                    self.hash_map[file_id] = real_path
            conn.close()
            self.is_valid_backup = True
        except Exception:
            pass

    def _index_known_hashes(self):
        for filename, (domain, rel_path) in self.KNOWN_DOMAIN_MAP.items():
            sha1_id = hashlib.sha1(f"{domain}-{rel_path}".encode("utf-8")).hexdigest()
            real_path = self._locate_hash_file(sha1_id)
            if real_path:
                self.file_map[(domain, rel_path)] = real_path
                self.hash_map[sha1_id] = real_path
                self.is_valid_backup = True

    def _fingerprint_sqlite_databases(self):
        """
        Deep SQLite schema fingerprinting: scans database tables to identify critical artifacts.
        """
        search_roots = [self.backup_dir]
        if os.path.exists(os.path.join(self.backup_dir, "Snapshot")):
            search_roots.append(os.path.join(self.backup_dir, "Snapshot"))

        for s_root in search_roots:
            for root, _, files in os.walk(s_root):
                for f in files:
                    full_p = os.path.join(root, f)
                    if not os.path.isfile(full_p) or os.path.getsize(full_p) < 1024:
                        continue

                    # Check SQLite 3 header (first 16 bytes)
                    try:
                        with open(full_p, "rb") as test_f:
                            hdr = test_f.read(16)
                            if not hdr.startswith(b"SQLite format 3\x00"):
                                continue

                        # Open and inspect tables
                        conn = connect_readonly_sqlite(full_p)
                        cur = conn.cursor()
                        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                        tbls = set(row[0] for row in cur.fetchall())
                        conn.close()

                        for art_name, sig_tables in self.SCHEMA_SIGNATURES.items():
                            if art_name not in self.fingerprinted_dbs:
                                if all(st in tbls for st in sig_tables):
                                    self.fingerprinted_dbs[art_name] = full_p
                                    self.is_valid_backup = True
                    except Exception:
                        pass

    def _locate_hash_file(self, file_id):
        search_roots = [self.backup_dir]
        if os.path.exists(os.path.join(self.backup_dir, "Snapshot")):
            search_roots.append(os.path.join(self.backup_dir, "Snapshot"))

        for root in search_roots:
            cand1 = os.path.join(root, file_id)
            cand2 = os.path.join(root, file_id[:2], file_id)
            if os.path.exists(cand2):
                return cand2
            if os.path.exists(cand1):
                return cand1
        return None

    def find_file(self, domain=None, relative_path=None, filename=None):
        # 1. Fingerprinted Database match
        if filename and filename in self.fingerprinted_dbs:
            return self.fingerprinted_dbs[filename]

        # 2. Direct domain + relativePath lookup
        if domain and relative_path:
            if (domain, relative_path) in self.file_map:
                return self.file_map[(domain, relative_path)]
            dyn_hash = hashlib.sha1(f"{domain}-{relative_path}".encode("utf-8")).hexdigest()
            path = self._locate_hash_file(dyn_hash)
            if path:
                return path

        # 3. Known filename lookup
        if filename and filename in self.KNOWN_DOMAIN_MAP:
            d, r = self.KNOWN_DOMAIN_MAP[filename]
            sha1_id = hashlib.sha1(f"{d}-{r}".encode("utf-8")).hexdigest()
            path = self._locate_hash_file(sha1_id)
            if path:
                return path

        return None

    def get_summary(self):
        return {
            "device_name": self.device_metadata.get("device_name", "Unknown"),
            "product_type": self.device_metadata.get("product_type", "iPhone"),
            "product_version": self.device_metadata.get("product_version", "iOS"),
            "serial_number": self.device_metadata.get("serial_number", "Unknown"),
            "udid": self.device_metadata.get("udid", "Unknown"),
            "is_encrypted": self.is_encrypted,
            "fingerprinted_artifacts": list(self.fingerprinted_dbs.keys()),
            "backup_dir": self.backup_dir
        }
