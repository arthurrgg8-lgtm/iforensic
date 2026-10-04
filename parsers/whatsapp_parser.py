import sqlite3
import os
from core.time_utils import mac_absolute_to_datetime, unix_to_datetime, format_datetime_utc, format_datetime_local
from core.db_utils import connect_readonly_sqlite

class WhatsAppParser:
    """
    Parses WhatsApp iOS database ChatStorage.sqlite (ZWAMESSAGE, ZWACHATSESSION).
    Extracts 1-on-1 and group chats, sender numbers, message text, media info, and timestamps.
    """

    def __init__(self, db_path):
        self.db_path = db_path
        self.messages = []

    def parse(self):
        if not self.db_path or not os.path.exists(self.db_path):
            return []

        try:
            conn = connect_readonly_sqlite(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            query = """
            SELECT 
                m.Z_PK as msg_id,
                m.ZTEXT as text_content,
                m.ZMESSAGEDATE as message_date,
                m.ZFROMJID as from_jid,
                m.ZTOJID as to_jid,
                m.ZISFROMME as is_from_me,
                m.ZMESSAGESTATUS as status,
                m.ZMEDIALOCALPATH as media_path,
                s.ZCONTACTJID as chat_jid,
                s.ZPARTNERNAME as partner_name
            FROM ZWAMESSAGE m
            LEFT JOIN ZWACHATSESSION s ON m.ZCHATSESSION = s.Z_PK
            WHERE m.ZTEXT IS NOT NULL OR m.ZMEDIALOCALPATH IS NOT NULL
            ORDER BY m.ZMESSAGEDATE ASC
            """
            cursor.execute(query)
            for row in cursor.fetchall():
                # Date in WhatsApp can be Mac Absolute or Unix timestamp
                date_val = row["message_date"]
                dt = mac_absolute_to_datetime(date_val)
                if not dt:
                    dt = unix_to_datetime(date_val)

                is_from_me = bool(row["is_from_me"])
                sender = "Self" if is_from_me else (row["from_jid"] or row["partner_name"] or "Unknown")
                recipient = (row["to_jid"] or row["partner_name"] or "Chat") if is_from_me else "Self"

                record = {
                    "source": "WhatsApp",
                    "msg_id": row["msg_id"],
                    "chat_name": row["partner_name"] or row["chat_jid"] or "Direct Chat",
                    "sender": sender,
                    "recipient": recipient,
                    "is_from_me": is_from_me,
                    "text": row["text_content"] or f"[Media Attachment: {row['media_path']}]",
                    "timestamp_utc": format_datetime_utc(dt),
                    "timestamp_local": format_datetime_local(dt),
                    "raw_datetime": dt
                }
                self.messages.append(record)

            conn.close()
        except Exception:
            pass

        return self.messages
