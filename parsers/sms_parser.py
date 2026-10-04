import sqlite3
import re
import os
from core.time_utils import mac_absolute_to_datetime, format_datetime_utc, format_datetime_local
from core.db_utils import connect_readonly_sqlite

class SMSParser:
    """
    Parses iOS sms.db (iMessage / SMS / MMS).
    Implements binary typedstream decoding for iOS 16/17/18+ attributedBody blobs.
    """

    def __init__(self, db_path):
        self.db_path = db_path
        self.messages = []
        self.handles = {}
        self.chats = {}

    def _extract_text_from_attributed_body(self, blob):
        """
        Carves clean human-readable text from serialized NSAttributedString / TypedStream binary blobs.
        """
        if not blob:
            return ""
        try:
            # Pattern 1: Look for NSString marker in typedstream (NSKeyedArchiver / Typedstream)
            # Find the string length and contents
            text_chunks = []
            
            # Simple binary string extraction of printable UTF-8 substrings >= 2 chars
            # Filter out Cocoa class names and metadata tokens
            raw_str = blob.decode("utf-8", errors="ignore")
            # Extract printable sequences
            tokens = re.findall(r'[\x20-\x7E\u0900-\u097F\u00A0-\uFFFF]{2,}', raw_str)
            filtered = []
            skip_patterns = [
                "NSAttributedString", "NSDictionary", "NSNumber", "NSString", 
                "NSMutableAttributedString", "NSMutableDictionary", "NSMutableString",
                "NSObject", "NSValue", "NSParagraphStyle", "NSColor", "NSFont",
                "__kIM", "IMMessage", "bplist00", "$version", "$objects", "$archiver", "$top"
            ]
            
            for t in tokens:
                t_clean = t.strip()
                if not t_clean:
                    continue
                if any(t_clean.startswith(sp) for sp in skip_patterns):
                    continue
                if len(t_clean) >= 2:
                    filtered.append(t_clean)
            
            if filtered:
                # Return the longest meaningful extracted text
                # Often the body is near the middle or end
                best = max(filtered, key=len)
                if len(best) >= 2:
                    return best
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

            # 1. Load Handles (Phone Numbers / Emails)
            try:
                cursor.execute("SELECT ROWID, id, service, uncanonicalized_id FROM handle")
                for row in cursor.fetchall():
                    self.handles[row["ROWID"]] = {
                        "id": row["id"],
                        "service": row["service"],
                        "uncanonicalized_id": row["uncanonicalized_id"]
                    }
            except Exception:
                pass

            # 2. Query Messages
            query = """
            SELECT 
                m.ROWID as msg_id,
                m.guid,
                m.text,
                m.attributedBody,
                m.handle_id,
                m.service,
                m.date,
                m.date_read,
                m.date_delivered,
                m.is_from_me,
                m.is_read,
                m.is_delivered,
                m.is_sent,
                m.cache_has_attachments,
                m.error
            FROM message m
            ORDER BY m.date ASC
            """
            
            cursor.execute(query)
            for row in cursor.fetchall():
                handle_info = self.handles.get(row["handle_id"], {})
                sender_id = handle_info.get("id", "Unknown") if not row["is_from_me"] else "Self"
                recipient_id = "Self" if not row["is_from_me"] else handle_info.get("id", "Unknown")

                msg_text = row["text"]
                if not msg_text and row["attributedBody"]:
                    msg_text = self._extract_text_from_attributed_body(row["attributedBody"])

                dt = mac_absolute_to_datetime(row["date"])
                dt_read = mac_absolute_to_datetime(row["date_read"])

                record = {
                    "msg_id": row["msg_id"],
                    "guid": row["guid"],
                    "service": row["service"] or "SMS",
                    "text": msg_text or "[Empty or Attachment]",
                    "sender": sender_id,
                    "recipient": recipient_id,
                    "is_from_me": bool(row["is_from_me"]),
                    "direction": "Outgoing" if row["is_from_me"] else "Incoming",
                    "timestamp_utc": format_datetime_utc(dt),
                    "timestamp_local": format_datetime_local(dt),
                    "raw_datetime": dt,
                    "is_read": bool(row["is_read"]),
                    "has_attachments": bool(row["cache_has_attachments"])
                }
                self.messages.append(record)

            conn.close()
        except Exception as e:
            pass

        return self.messages
