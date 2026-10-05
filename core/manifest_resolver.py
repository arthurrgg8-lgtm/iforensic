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
        "sms.db": [("HomeDomain", "Library/SMS/sms.db")],
        "CallHistory.storedata": [("HomeDomain", "Library/CallHistoryDB/CallHistory.storedata")],
        "AddressBook.sqlitedb": [("HomeDomain", "Library/AddressBook/AddressBook.sqlitedb")],
        "AddressBookImages.sqlitedb": [("HomeDomain", "Library/AddressBook/AddressBookImages.sqlitedb")],
        "NoteStore.sqlite": [("AppDomainGroup-group.com.apple.notes", "NoteStore.sqlite")],
        "SafariHistory.db": [("HomeDomain", "Library/Safari/History.db")],
        "Photos.sqlite": [("CameraRollDomain", "Media/PhotoData/Photos.sqlite")],
        "DataUsage.sqlite": [("WirelessDomain", "Library/Databases/DataUsage.sqlite")],
        "ChatStorage.sqlite": [
            ("AppDomainGroup-group.net.whatsapp.WhatsApp.shared", "ChatStorage.sqlite"),
            ("AppDomainGroup-group.net.whatsapp.WhatsAppSMB.shared", "ChatStorage.sqlite"),
            ("AppDomain-net.whatsapp.WhatsApp", "Documents/ChatStorage.sqlite"),
            ("AppDomain-net.whatsapp.WhatsAppSMB", "Documents/ChatStorage.sqlite")
        ],
        "ContactsV2.sqlite": [
            ("AppDomainGroup-group.net.whatsapp.WhatsAppSMB.shared", "ContactsV2.sqlite"),
            ("AppDomainGroup-group.net.whatsapp.WhatsApp.shared", "ContactsV2.sqlite"),
            ("AppDomain-net.whatsapp.WhatsAppSMB", "Documents/ContactsV2.sqlite"),
            ("AppDomain-net.whatsapp.WhatsApp", "Documents/ContactsV2.sqlite")
        ],
        "Truecaller.sqlite": [("AppDomain-com.truesoftware.TrueCaller", "Library/Application Support/db.sqlite")],
        "CloudRecordings.db": [("AppDomainGroup-group.com.apple.VoiceMemos.shared", "Recordings/CloudRecordings.db")],
        "Recordings.sqlite": [("MediaDomain", "Media/Recordings/Recordings.sqlite")],
        "voicemail.db": [("HomeDomain", "Library/Voicemail/voicemail.db")],
        "tgdata.db": [
            ("AppDomain-ph.telegra.Telegraph", "Documents/tgdata.db"),
            ("AppDomain-ph.telegra.Telegraph", "Documents/store.sqlite"),
            ("AppDomain-org.telegram.Telegram-iOS", "Documents/tgdata.db"),
            ("AppDomainGroup-group.ph.telegra.Telegraph", "tgdata.db")
        ],
        "signal.sqlite": [
            ("AppDomainGroup-group.org.whispersystems.signal", "Documents/signal.sqlite"),
            ("AppDomain-org.whispersystems.signal", "Documents/signal.sqlite")
        ],
        "teams.db": [
            ("AppDomain-com.microsoft.skype.teams", "Library/Application Support/teams.db"),
            ("AppDomain-com.microsoft.skype.teams", "Documents/teams.db")
        ],
        "protonmail.db": [("AppDomain-ch.protonmail.protonmail", "Documents/protonmail.db")],
        "lightspeed.db": [
            ("AppDomain-com.facebook.Messenger", "Documents/lightspeed.db"),
            ("AppDomain-com.facebook.Messenger", "Documents/threads.db"),
            ("AppDomain-com.facebook.Messenger", "Documents/orca.sqlite"),
            ("AppDomain-com.facebook.Messenger", "Documents/messenger.sqlite"),
            ("AppDomain-com.facebook.Messenger", "Documents/LSDatabase.sqlite"),
            ("AppDomainGroup-group.com.facebook.Messenger", "lightspeed.db"),
            ("AppDomain-com.facebook.Facebook", "Documents/messenger.sqlite")
        ],
        "Viber.sqlite": [
            ("AppDomain-com.viber", "Documents/Contacts.data"),
            ("AppDomain-com.viber", "Documents/Viber.sqlite"),
            ("AppDomain-com.viber", "Documents/viber.db"),
            ("AppDomain-com.viber", "Documents/Messages.data"),
            ("AppDomainGroup-group.com.viber", "Contacts.data")
        ],
        "direct_v2.sqlite": [
            ("AppDomain-com.burbn.instagram", "Documents/direct_v2.sqlite"),
            ("AppDomain-com.burbn.instagram", "Documents/threads.db"),
            ("AppDomain-com.burbn.instagram", "Documents/messages.db")
        ],
        "discord.sqlite": [
            ("AppDomain-com.hammerandchisel.discord", "Documents/discord.sqlite"),
            ("AppDomain-com.hammerandchisel.discord", "Documents/chat.db")
        ],
        "Line.sqlite": [
            ("AppDomain-jp.naver.line", "Documents/Line.sqlite"),
            ("AppDomain-jp.naver.line", "Documents/chat.db")
        ],
        "MM.sqlite": [
            ("AppDomain-com.tencent.xin", "Documents/MM.sqlite"),
            ("AppDomain-com.tencent.xin", "Documents/message.db")
        ],
        "skype.db": [
            ("AppDomain-com.skype.skype", "Documents/main.db"),
            ("AppDomain-com.skype.skype", "Documents/skype.db")
        ],
        "keychain-backup.plist": [("KeychainDomain", "keychain-backup.plist")],
        "Keychain.plist": [("KeychainDomain", "Keychain.plist")],
        "TrustStore.sqlite3": [("KeychainDomain", "TrustStore.sqlite3")]
    }

    SCHEMA_SIGNATURES = {
        "sms.db": ["message", "handle", "chat"],
        "CallHistory.storedata": ["ZCALLRECORD"],
        "AddressBook.sqlitedb": ["ABPerson"],
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
        "protonmail.db": ["messages"],
        "lightspeed.db": ["messages", "threads"],
        "Viber.sqlite": ["ZMESSAGE"],
        "Contacts.data": ["ZMESSAGE"],
        "direct_v2.sqlite": ["messages"],
        "discord.sqlite": ["messages"],
        "Line.sqlite": ["ZMESSAGE"],
        "MM.sqlite": ["Chat_Message"]
    }

    SKIP_MEDIA_EXTS = {'.jpg', '.jpeg', '.heic', '.png', '.gif', '.mov', '.mp4', '.m4a', '.opus', '.wav', '.aac', '.mp3', '.pdf', '.docx', '.zip'}

    def __init__(self, backup_dir, deep_fingerprint=True, decrypted_manifest_path=None, crypto_engine=None):
        self.backup_dir = os.path.abspath(backup_dir)
        self.snapshot_dir = os.path.join(self.backup_dir, "Snapshot") if os.path.exists(os.path.join(self.backup_dir, "Snapshot")) else self.backup_dir
        self.crypto_engine = crypto_engine
        self.manifest_db_path = decrypted_manifest_path or self._find_first(["Manifest.db", "Snapshot/Manifest.db"])
        self.info_plist_path = self._find_first(["Info.plist", "Snapshot/Info.plist"])
        self.manifest_plist_path = self._find_first(["Manifest.plist", "Snapshot/Manifest.plist"])
        self.status_plist_path = self._find_first(["Status.plist", "Snapshot/Status.plist"])

        self.is_valid_backup = False
        self.is_encrypted = False
        self.device_metadata = {}
        self.file_map = {}   # { (domain, relative_path): real_disk_path }
        self.hash_map = {}   # { file_id: real_disk_path }
        self.file_blob_map = {} # { real_path_or_file_id: file_blob }
        self.decrypted_file_cache = {} # { real_path: decrypted_path }
        self.fingerprinted_dbs = {} # { artifact_name: real_disk_path }

        self._load_metadata()
        self._index_manifest_db()
        self._index_known_hashes()
        if deep_fingerprint:
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
            cursor.execute("SELECT fileID, domain, relativePath, file FROM Files")
            for file_id, domain, rel_path, file_blob in cursor.fetchall():
                real_path = self._locate_hash_file(file_id)
                if real_path:
                    self.file_map[(domain, rel_path)] = real_path
                    self.hash_map[file_id] = real_path
                    if file_blob:
                        self.file_blob_map[real_path] = file_blob
                        self.file_blob_map[file_id] = file_blob
            conn.close()
            self.is_valid_backup = True
        except Exception:
            pass

    def _index_known_hashes(self):
        for filename, candidates in self.KNOWN_DOMAIN_MAP.items():
            for domain, rel_path in candidates:
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

    def _fingerprinted_match(self, filename):
        if filename in self.fingerprinted_dbs:
            return self.fingerprinted_dbs[filename]
        return None

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

    def _resolve_raw_path(self, domain=None, relative_path=None, filename=None):
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
            for d, r in self.KNOWN_DOMAIN_MAP[filename]:
                if (d, r) in self.file_map:
                    return self.file_map[(d, r)]
                sha1_id = hashlib.sha1(f"{d}-{r}".encode("utf-8")).hexdigest()
                path = self._locate_hash_file(sha1_id)
                if path:
                    return path

        # 4. Fallback search across indexed file_map by filename
        if filename:
            for (dom, rel_p), real_p in self.file_map.items():
                if rel_p == filename or rel_p.endswith("/" + filename) or rel_p.endswith("\\" + filename):
                    return real_p

        return None

    def find_file(self, domain=None, relative_path=None, filename=None):
        raw_path = self._resolve_raw_path(domain=domain, relative_path=relative_path, filename=filename)
        if not raw_path or not os.path.exists(raw_path):
            return None

        # Check if file has already been decrypted and cached
        if raw_path in self.decrypted_file_cache:
            return self.decrypted_file_cache[raw_path]

        # If crypto engine is available and backup is encrypted, attempt on-the-fly payload decryption
        if self.crypto_engine and getattr(self.crypto_engine, "unwrapped_keys", None):
            # Check if file is already plaintext
            is_plaintext = False
            try:
                with open(raw_path, "rb") as test_f:
                    hdr = test_f.read(16)
                    if hdr.startswith(b"SQLite format 3\x00") or hdr.startswith(b"bplist00") or hdr.startswith(b"<?xml"):
                        is_plaintext = True
            except Exception:
                pass

            if not is_plaintext:
                file_blob = self.file_blob_map.get(raw_path)
                if not file_blob:
                    # Look up by hash
                    file_id = os.path.basename(raw_path)
                    file_blob = self.file_blob_map.get(file_id)

                if file_blob:
                    staging_dir = os.path.join(self.backup_dir, "decrypted_staging")
                    os.makedirs(staging_dir, exist_ok=True)
                    clean_name = filename or os.path.basename(relative_path or "decrypted_file.bin")
                    target_dec_path = os.path.join(staging_dir, f"{os.path.basename(raw_path)}_{clean_name}")
                    
                    ok, _ = self.crypto_engine.decrypt_file(raw_path, file_blob, target_dec_path)
                    if ok and os.path.exists(target_dec_path):
                        self._stage_wal_and_shm_companions(target_dec_path, domain=domain, relative_path=relative_path, filename=filename)
                        self.decrypted_file_cache[raw_path] = target_dec_path
                        return target_dec_path

        self._stage_wal_and_shm_companions(raw_path, domain=domain, relative_path=relative_path, filename=filename)
        return raw_path

    def find_all_files(self, domain=None, relative_path=None, filename=None, domain_contains=None, filename_contains=None):
        """
        Finds and returns a list of all matching files across different domains or paths.
        """
        raw_candidates = []
        for (dom, rel_p), real_p in self.file_map.items():
            if domain and dom != domain:
                continue
            if domain_contains and domain_contains.lower() not in dom.lower():
                continue
            if filename:
                f_base = os.path.basename(rel_p)
                if f_base.lower() != filename.lower() and rel_p.lower() != filename.lower():
                    continue
            if filename_contains:
                if filename_contains.lower() not in rel_p.lower():
                    continue
            if relative_path and rel_p != relative_path:
                continue
            if real_p and os.path.exists(real_p) and (real_p, dom, rel_p) not in raw_candidates:
                raw_candidates.append((real_p, dom, rel_p))

        # Check known domain map candidates as well
        if filename and filename in self.KNOWN_DOMAIN_MAP:
            for d, r in self.KNOWN_DOMAIN_MAP[filename]:
                sha1_id = hashlib.sha1(f"{d}-{r}".encode("utf-8")).hexdigest()
                p = self._locate_hash_file(sha1_id)
                if p and os.path.exists(p) and (p, d, r) not in raw_candidates:
                    raw_candidates.append((p, d, r))

        resolved_list = []
        for _, dom, rel_p in raw_candidates:
            res = self.find_file(domain=dom, relative_path=rel_p)
            if res and res not in resolved_list:
                resolved_list.append(res)
        return resolved_list

    def _stage_wal_and_shm_companions(self, target_db_path, domain=None, relative_path=None, filename=None):
        """
        Locates and stages companion Write-Ahead Log (-wal) and Shared Memory (-shm) files
        adjacent to the database file so SQLite merges all uncommitted and live transactions.
        """
        if not target_db_path or not os.path.exists(target_db_path):
            return

        db_exts = ('.db', '.sqlite', '.sqlite3', '.sqlitedb', '.storedata')
        if not any(target_db_path.lower().endswith(ext) for ext in db_exts):
            return

        # Determine domain and relative_path if not provided
        if not domain or not relative_path:
            if filename and filename in self.KNOWN_DOMAIN_MAP:
                domain, relative_path = self.KNOWN_DOMAIN_MAP[filename]

        if not domain or not relative_path:
            return

        for suffix in ["-wal", "-shm"]:
            comp_rel = f"{relative_path}{suffix}"
            comp_raw = self._resolve_raw_path(domain=domain, relative_path=comp_rel)
            if comp_raw and os.path.exists(comp_raw):
                target_comp_path = f"{target_db_path}{suffix}"
                if os.path.exists(target_comp_path):
                    continue

                # Check if companion needs decryption
                if self.crypto_engine and getattr(self.crypto_engine, "unwrapped_keys", None):
                    file_blob = self.file_blob_map.get(comp_raw) or self.file_blob_map.get(os.path.basename(comp_raw))
                    if file_blob:
                        self.crypto_engine.decrypt_file(comp_raw, file_blob, target_comp_path)
                
                if not os.path.exists(target_comp_path):
                    try:
                        import shutil
                        shutil.copy2(comp_raw, target_comp_path)
                    except Exception:
                        pass

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
