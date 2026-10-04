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
                cur.execute("""
                    SELECT 
                        ROWID,
                        sender,
                        date,
                        duration,
                        flags,
                        transcription
                    FROM voicemail
                    ORDER BY date DESC
                """)
                for row in cur.fetchall():
                    dt_utc, dt_loc = apple_to_iso(row["date"])
                    sender = row["sender"] or "Unknown Sender"
                    caller_name = self.contacts_parser.resolve_number(sender) if self.contacts_parser else sender
                    transcription = row["transcription"] if "transcription" in row.keys() else ""

                    self.voicemails.append({
                        "id": row["ROWID"],
                        "type": "Voicemail",
                        "sender": sender,
                        "caller_name": caller_name,
                        "duration_seconds": row["duration"] or 0,
                        "timestamp_utc": dt_utc,
                        "timestamp_local": dt_loc,
                        "transcription": transcription or "[No transcription available]"
                    })

            conn.close()
        except Exception:
            pass

    def _carve_audio_files(self):
        """
        Scans and indexes all audio files (.m4a, .opus, .aac, .amr, .wav, .mp3) in the backup.
        """
        if not self.resolver:
            return

        backup_dir = self.resolver.backup_dir
        audio_extensions = {".m4a", ".opus", ".aac", ".amr", ".wav", ".mp3", ".caf"}

        for root, _, files in os.walk(backup_dir):
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in audio_extensions:
                    full_p = os.path.join(root, f)
                    try:
                        size_kb = round(os.path.getsize(full_p) / 1024, 2)
                        self.carved_audio_files.append({
                            "filename": f,
                            "extension": ext,
                            "size_kb": size_kb,
                            "path": full_p
                        })
                    except Exception:
                        pass
