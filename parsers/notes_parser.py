import sqlite3
import gzip
import re
import os
from core.time_utils import mac_absolute_to_datetime, format_datetime_utc, format_datetime_local
from core.db_utils import connect_readonly_sqlite

class NotesParser:
    """
    Parses iOS NoteStore.sqlite (Apple Cloud / Local Notes).
    Decompresses ZICNOTEDATA.ZDATA gzip blobs and parses Protobuf serialized note text cleanly.
    """

    def __init__(self, db_path):
        self.db_path = db_path
        self.notes = []

    def _extract_clean_protobuf_text(self, zdata_blob):
        if not zdata_blob:
            return ""
        try:
            decomp = gzip.decompress(zdata_blob)
            
            # Protobuf decoding:
            # Apple Notes NoteStoreProto stores the note body in Document.note.note_text (field tag 0x12).
            # Look for 0x1a followed by length, then 0x12 followed by text string length.
            idx = decomp.find(b'\x1a')
            while idx != -1 and idx < len(decomp) - 2:
                pos = idx + 1
                length = 0
                shift = 0
                while pos < len(decomp):
                    b = decomp[pos]
                    length |= (b & 0x7f) << shift
                    pos += 1
                    if not (b & 0x80):
                        break
                    shift += 7
                
                if pos < len(decomp) and decomp[pos] == 0x12:
                    pos += 1
                    text_len = 0
                    shift = 0
                    while pos < len(decomp):
                        b = decomp[pos]
                        text_len |= (b & 0x7f) << shift
                        pos += 1
                        if not (b & 0x80):
                            break
                        shift += 7
                    
                    if pos + text_len <= len(decomp):
                        raw_bytes = decomp[pos:pos+text_len]
                        try:
                            clean_text = raw_bytes.decode('utf-8')
                        except UnicodeDecodeError:
                            clean_text = raw_bytes.decode('utf-8', errors='ignore')
                        
                        # Strip any stray leading non-printable control characters
                        clean_text = re.sub(r'^[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]+', '', clean_text)
                        return clean_text.strip()
                
                idx = decomp.find(b'\x1a', idx + 1)
            
            # Fallback for older note formats
            raw_str = decomp.decode("utf-8", errors="ignore")
            matches = re.findall(r'[\x20-\x7E\u0900-\u097F\n\r\t]{4,}', raw_str)
            filtered = [m.strip() for m in matches if not m.strip().startswith("com.apple") and not m.strip().startswith("protobuf") and len(m.strip()) > 3]
            if filtered:
                return "\n".join(filtered)
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

            # Dynamic column discovery for Apple CoreData version shifts (iOS 12 - 18+)
            cursor.execute("PRAGMA table_info(ZICCLOUDSYNCINGOBJECT)")
            cols = set(r["name"] for r in cursor.fetchall())

            title_col = "n.ZTITLE1" if "ZTITLE1" in cols else ("n.ZTITLE" if "ZTITLE" in cols else ("n.ZTITLE2" if "ZTITLE2" in cols else "NULL"))
            snippet_col = "n.ZSNIPPET" if "ZSNIPPET" in cols else "NULL"
            creation_col = "n.ZCREATIONDATE" if "ZCREATIONDATE" in cols else "0"
            mod_col = "n.ZMODIFICATIONDATE1" if "ZMODIFICATIONDATE1" in cols else ("n.ZMODIFICATIONDATE" if "ZMODIFICATIONDATE" in cols else (creation_col or "0"))
            del_col = "n.ZMARKEDFORDELETION" if "ZMARKEDFORDELETION" in cols else "0"
            folder_title_col = "f.ZTITLE2" if "ZTITLE2" in cols else ("f.ZTITLE" if "ZTITLE" in cols else "NULL")
            folder_fk = "n.ZFOLDER" if "ZFOLDER" in cols else "NULL"

            # Resolve Account link (ZACCOUNT4, ZACCOUNT3, ZACCOUNT2, ZACCOUNT)
            acc_fk = next((f"n.{c}" for c in ["ZACCOUNT4", "ZACCOUNT3", "ZACCOUNT2", "ZACCOUNT"] if c in cols), "NULL")
            acc_name_col = "a.ZNAME" if "ZNAME" in cols else "NULL"

            # Check if ZICNOTEDATA exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ZICNOTEDATA'")
            has_notedata = bool(cursor.fetchone())
            data_join = "LEFT JOIN ZICNOTEDATA d ON n.Z_PK = d.ZNOTE" if has_notedata else ""
            data_col = "d.ZDATA" if has_notedata else "NULL"

            query = f"""
            SELECT 
                n.Z_PK as note_pk,
                {title_col} as title,
                {snippet_col} as snippet,
                {creation_col} as creation_date,
                {mod_col} as modification_date,
                {del_col} as is_deleted,
                {data_col} as data_blob,
                {folder_title_col} as folder_name,
                {acc_name_col} as account_name
            FROM ZICCLOUDSYNCINGOBJECT n
            {data_join}
            LEFT JOIN ZICCLOUDSYNCINGOBJECT f ON ({folder_fk} = f.Z_PK AND {folder_fk} IS NOT NULL)
            LEFT JOIN ZICCLOUDSYNCINGOBJECT a ON ({acc_fk} = a.Z_PK AND {acc_fk} IS NOT NULL)
            WHERE {title_col} IS NOT NULL OR {data_col} IS NOT NULL
            ORDER BY {mod_col} DESC
            """

            cursor.execute(query)
            for row in cursor.fetchall():
                created_dt = mac_absolute_to_datetime(row["creation_date"])
                mod_dt = mac_absolute_to_datetime(row["modification_date"])

                full_text = self._extract_clean_protobuf_text(row["data_blob"])
                raw_title = row["title"] or (full_text.splitlines()[0] if full_text else "Untitled Note")
                title = raw_title.strip() if raw_title else "Untitled Note"

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

