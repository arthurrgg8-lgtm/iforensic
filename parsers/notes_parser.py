import sqlite3
import gzip
import re
import os
from core.time_utils import mac_absolute_to_datetime, format_datetime_utc, format_datetime_local
from core.db_utils import connect_readonly_sqlite

class NotesParser:
    """
    Parses iOS NoteStore.sqlite (Apple Cloud / Local Notes).
    Decompresses ZICNOTEDATA.ZDATA gzip blobs and extracts Google Protobuf serialized note text.
    """

    def __init__(self, db_path):
        self.db_path = db_path
        self.notes = []

    def _decompress_and_extract_text(self, zdata_blob):
        if not zdata_blob:
            return ""
        try:
            # Gzip Decompression
            decompressed = gzip.decompress(zdata_blob)
            
            # Protobuf string extraction
            raw_str = decompressed.decode("utf-8", errors="ignore")
            # Extract printable character lines and strings
            lines = []
            for token in re.findall(r'[\x20-\x7E\u0900-\u097F\n\r\t]{2,}', raw_str):
                cleaned = token.strip()
                # Skip protobuf field headers and noise
                if len(cleaned) >= 2 and not cleaned.startswith("protobuf") and not cleaned.startswith("com.apple"):
                    lines.append(cleaned)
            
            if lines:
                return "\n".join(lines)
        except Exception:
            pass
        return ""

    def parse(self):
        if not self.db_path or not os.path.exists(self.db_path):
            return []

        try:
            conn = connect_readonly_sqlite(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            query = """
            SELECT 
                n.Z_PK as note_pk,
                n.ZTITLE1 as title,
                n.ZSNIPPET as snippet,
                n.ZCREATIONDATE as creation_date,
                n.ZMODIFICATIONDATE1 as modification_date,
                n.ZMARKEDFORDELETION as is_deleted,
                d.ZDATA as data_blob,
                f.ZTITLE2 as folder_name,
                a.ZNAME as account_name
            FROM ZICCLOUDSYNCINGOBJECT n
            LEFT JOIN ZICNOTEDATA d ON n.Z_PK = d.ZNOTE
            LEFT JOIN ZICCLOUDSYNCINGOBJECT f ON n.ZFOLDER = f.Z_PK
            LEFT JOIN ZICCLOUDSYNCINGOBJECT a ON n.ZACCOUNT4 = a.Z_PK
            WHERE n.ZTITLE1 IS NOT NULL OR d.ZDATA IS NOT NULL
            ORDER BY n.ZMODIFICATIONDATE1 DESC
            """

            cursor.execute(query)
            for row in cursor.fetchall():
                created_dt = mac_absolute_to_datetime(row["creation_date"])
                mod_dt = mac_absolute_to_datetime(row["modification_date"])

                full_text = self._decompress_and_extract_text(row["data_blob"])
                title = row["title"] or (full_text.splitlines()[0] if full_text else "Untitled Note")

                # Heuristic tag detection
                lower_text = (full_text or "").lower()
                tags = []
                if any(k in lower_text for k in ["pass", "pwd", "pin", "otp", "login", "key"]):
                    tags.append("Credentials/PIN")
                if any(k in lower_text for k in ["bank", "ac", "account", "nabil", "nic", "esewa", "khalti", "wise", "iban", "swift", "balance"]):
                    tags.append("Financial/Banking")
                if any(k in lower_text for k in ["passport", "citizenship", "aadhaar", "pan", "nid"]):
                    tags.append("Identity Document")

                record = {
                    "note_id": row["note_pk"],
                    "title": title,
                    "snippet": row["snippet"] or "",
                    "folder": row["folder_name"] or "Default",
                    "account": row["account_name"] or "iCloud / Local",
                    "full_content": full_text or row["snippet"] or "[Empty Note]",
                    "is_deleted": bool(row["is_deleted"]),
                    "tags": tags,
                    "created_utc": format_datetime_utc(created_dt),
                    "modified_utc": format_datetime_utc(mod_dt),
                    "created_local": format_datetime_local(created_dt),
                    "modified_local": format_datetime_local(mod_dt),
                    "raw_datetime": mod_dt or created_dt
                }
                self.notes.append(record)

            conn.close()
        except Exception:
            pass

        return self.notes
