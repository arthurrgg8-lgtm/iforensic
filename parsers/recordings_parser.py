import os
import sqlite3
import shutil
from datetime import datetime
from core.time_utils import apple_to_iso, parse_any_time
from core.db_utils import connect_readonly_sqlite

class RecordingsParser:
    """
    Parses iOS Audio Recordings:
    1. Apple Voice Memos (Recordings.sqlite / CloudRecordings.db)
    2. Voicemail Audio & Transcriptions (voicemail.db)
    3. WhatsApp Voice Notes & Audio Attachments
    4. Carved raw audio files (.m4a, .opus, .aac, .amr, .wav, .mp3)
    """

    def __init__(self, manifest_resolver=None, output_dir=None, contacts_parser=None):
        self.resolver = manifest_resolver
        self.output_dir = output_dir
        self.contacts_parser = contacts_parser
        self.recordings = []
        self.voicemails = []
        self.carved_audio_files = []

    def parse(self):
        self._parse_voice_memos()
        self._parse_voicemails()
        self._carve_audio_files()

        return {
            "voice_memos": self.recordings,
            "voicemails": self.voicemails,
            "carved_audio_files": self.carved_audio_files,
            "total_audio_artifacts": len(self.recordings) + len(self.voicemails) + len(self.carved_audio_files)
        }

    def _parse_voice_memos(self):
        if not self.resolver:
            return

        db_path = self.resolver.find_file(
            domain="AppDomainGroup-group.com.apple.VoiceMemos.shared",
            relative_path="Recordings/CloudRecordings.db",
            filename="CloudRecordings.db"
        ) or self.resolver.find_file(
            domain="MediaDomain",
            relative_path="Media/Recordings/Recordings.sqlite",
            filename="Recordings.sqlite"
        )

        if not db_path or not os.path.exists(db_path):
            return

        try:
            conn = connect_readonly_sqlite(db_path)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cur.fetchall()]

            if "ZCLOUDRECORDING" in tables:
                cur.execute("""
                    SELECT 
                        Z_PK,
                        ZPATH,
                        ZDATE,
                        ZDURATION,
                        ZCUSTOMLABEL,
                        ZENCRYPTEDTITLE,
                        ZEVICTIONDATE
                    FROM ZCLOUDRECORDING
                    ORDER BY ZDATE DESC
                """)
                for row in cur.fetchall():
                    dt_utc, dt_loc = apple_to_iso(row["ZDATE"])
                    title = row["ZCUSTOMLABEL"] or row["ZENCRYPTEDTITLE"] or f"Voice Memo {row['Z_PK']}"
                    duration = round(float(row["ZDURATION"] or 0), 2)

                    self.recordings.append({
                        "id": row["Z_PK"],
                        "type": "Voice Memo (Cloud)",
                        "title": title,
                        "duration_seconds": duration,
                        "timestamp_utc": dt_utc,
                        "timestamp_local": dt_loc,
                        "file_rel_path": row["ZPATH"] or "",
                        "deleted": bool(row["ZEVICTIONDATE"])
                    })

            elif "ZRECORDING" in tables:
                cur.execute("""
                    SELECT 
                        Z_PK,
                        ZPATH,
                        ZDATE,
                        ZDURATION,
                        ZCUSTOMLABEL
                    FROM ZRECORDING
                    ORDER BY ZDATE DESC
                """)
                for row in cur.fetchall():
                    dt_utc, dt_loc = apple_to_iso(row["ZDATE"])
                    title = row["ZCUSTOMLABEL"] or f"Voice Memo {row['Z_PK']}"
                    duration = round(float(row["ZDURATION"] or 0), 2)

                    self.recordings.append({
                        "id": row["Z_PK"],
                        "type": "Voice Memo",
                        "title": title,
                        "duration_seconds": duration,
                        "timestamp_utc": dt_utc,
                        "timestamp_local": dt_loc,
                        "file_rel_path": row["ZPATH"] or "",
                        "deleted": False
                    })

            conn.close()
        except Exception:
            pass

    def _parse_voicemails(self):
        if not self.resolver:
            return

        db_path = self.resolver.find_file(
            domain="HomeDomain",
            relative_path="Library/Voicemail/voicemail.db",
            filename="voicemail.db"
        )

        if not db_path or not os.path.exists(db_path):
            return

        try:
            conn = connect_readonly_sqlite(db_path)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cur.fetchall()]

            if "voicemail" in tables:
                cur.execute("PRAGMA table_info(voicemail)")
                vm_cols = set(r["name"] for r in cur.fetchall())
                trans_col = "transcription" if "transcription" in vm_cols else "NULL as transcription"
                sender_col = "sender" if "sender" in vm_cols else "NULL as sender"
                date_col = "date" if "date" in vm_cols else "0 as date"
                dur_col = "duration" if "duration" in vm_cols else "0 as duration"
                flags_col = "flags" if "flags" in vm_cols else "0 as flags"
                trash_col = "trashed_date" if "trashed_date" in vm_cols else "NULL as trashed_date"

                cur.execute(f"""
                    SELECT 
                        ROWID,
                        {sender_col},
                        {date_col},
                        {dur_col},
                        {flags_col},
                        {trans_col},
                        {trash_col}
                    FROM voicemail
                    ORDER BY date DESC
                """)
                for row in cur.fetchall():
                    dt_utc, dt_loc = apple_to_iso(row["date"])
                    sender = row["sender"] or "Unknown Sender"
                    caller_name = self.contacts_parser.resolve_number(sender) if self.contacts_parser else sender
                    transcription = row["transcription"] or ""

                    self.voicemails.append({
                        "id": row["ROWID"],
                        "type": "Voicemail",
                        "sender": sender,
                        "caller_name": caller_name,
                        "duration_seconds": row["duration"] or 0,
                        "timestamp_utc": dt_utc,
                        "timestamp_local": dt_loc,
                        "is_trashed": bool(row["trashed_date"]),
                        "transcription": transcription or "[No transcription available]"
                    })

            conn.close()
        except Exception:
            pass

    def _carve_audio_files(self):
        """
        Scans, maps, and indexes all audio files (.m4a, .opus, .caf, .wav, .aac, .amr, .mp3)
        from Manifest.db hashed evidence files and disk locations.
        """
        if not self.resolver:
            return

        audio_extensions = {".m4a", ".opus", ".aac", ".amr", ".wav", ".mp3", ".caf"}
        seen_paths = set()

        # 1. Primary Strategy: Query Manifest.db for mapped audio files
        manifest_db = getattr(self.resolver, "manifest_db_path", None)
        if manifest_db and os.path.exists(manifest_db):
            try:
                conn = connect_readonly_sqlite(manifest_db)
                cur = conn.cursor()
                ext_conditions = " OR ".join([f"relativePath LIKE '%{ext}'" for ext in audio_extensions])
                cur.execute(f"SELECT fileID, domain, relativePath FROM Files WHERE ({ext_conditions})")
                for file_id, domain, rel_path in cur.fetchall():
                    real_p = self.resolver.hash_map.get(file_id) if hasattr(self.resolver, "hash_map") else None
                    if not real_p or not os.path.exists(real_p):
                        real_p = self.resolver.find_file(domain=domain, relative_path=rel_path)

                    if real_p and os.path.exists(real_p) and real_p not in seen_paths:
                        seen_paths.add(real_p)
                        fname = os.path.basename(rel_path)
                        ext = os.path.splitext(fname)[1].lower()
                        category = "Audio File"
                        if "VoiceMemos" in domain or "Recordings" in rel_path:
                            category = "Apple Voice Memo"
                        elif "Voicemail" in domain or "Voicemail" in rel_path:
                            category = "Voicemail Audio"
                        elif "WhatsApp" in domain or "WhatsApp" in rel_path:
                            category = "WhatsApp Voice Note / Audio"
                        elif "Media" in domain:
                            category = "User Media Audio"

                        try:
                            size_kb = round(os.path.getsize(real_p) / 1024, 2)
                        except Exception:
                            size_kb = 0.0

                        self.carved_audio_files.append({
                            "filename": fname,
                            "relative_path": rel_path,
                            "domain": domain,
                            "category": category,
                            "extension": ext,
                            "size_kb": size_kb,
                            "path": real_p
                        })
                conn.close()
            except Exception:
                pass

        # 2. Secondary Strategy: Scan backup directory on disk (for flattened or raw files)
        backup_dir = self.resolver.backup_dir
        if backup_dir and os.path.exists(backup_dir):
            for root, _, files in os.walk(backup_dir):
                for f in files:
                    ext = os.path.splitext(f)[1].lower()
                    if ext in audio_extensions:
                        full_p = os.path.join(root, f)
                        if full_p in seen_paths:
                            continue
                        seen_paths.add(full_p)
                        try:
                            size_kb = round(os.path.getsize(full_p) / 1024, 2)
                            self.carved_audio_files.append({
                                "filename": f,
                                "relative_path": os.path.relpath(full_p, backup_dir),
                                "domain": "LocalDisk",
                                "category": "Audio File",
                                "extension": ext,
                                "size_kb": size_kb,
                                "path": full_p
                            })
                        except Exception:
                            pass
