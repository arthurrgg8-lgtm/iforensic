import sqlite3
import os
import re
from core.time_utils import mac_absolute_to_datetime, unix_to_datetime, format_datetime_utc, format_datetime_local
from core.db_utils import connect_readonly_sqlite

class WhatsAppParser:
    """
    Parses WhatsApp (Standard) and WhatsApp Business (WhatsApp SMB) iOS databases (ChatStorage.sqlite).
    Extracts 1-on-1 chats, group chats, sender numbers, contact names, message text,
    system notices, media attachments, and timestamps in pure plain text.
    """

    def __init__(self, db_paths, contacts_resolver=None):
        if isinstance(db_paths, (list, tuple, set)):
            self.db_paths = [p for p in db_paths if p and os.path.exists(p)]
        elif db_paths and os.path.exists(db_paths):
            self.db_paths = [db_paths]
        else:
            self.db_paths = []
        self.contacts_resolver = contacts_resolver
        self.messages = []

    def parse(self):
        if not self.db_paths:
            return []

        all_records = []
        seen_keys = set()

        for db_path in self.db_paths:
            app_variant = "WhatsApp Business" if ("WhatsAppSMB" in db_path or "business" in db_path.lower()) else "WhatsApp"
            try:
                conn = connect_readonly_sqlite(db_path)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                # Check existing columns in ZWAMESSAGE
                cursor.execute("PRAGMA table_info(ZWAMESSAGE)")
                cols = set(r["name"] for r in cursor.fetchall())

                # Build flexible query based on schema
                from_jid_col = "m.ZFROMJID" if "ZFROMJID" in cols else "NULL"
                to_jid_col = "m.ZTOJID" if "ZTOJID" in cols else "NULL"
                media_path_col = "m.ZMEDIALOCALPATH" if "ZMEDIALOCALPATH" in cols else "NULL"
                media_type_col = "m.ZMEDIAITEM" if "ZMEDIAITEM" in cols else "NULL"
                is_del_col = "m.ZISDELETED" if "ZISDELETED" in cols else "0"

                query = f"""
                SELECT 
                    m.Z_PK as msg_id,
                    m.ZTEXT as text_content,
                    m.ZMESSAGEDATE as message_date,
                    {from_jid_col} as from_jid,
                    {to_jid_col} as to_jid,
                    m.ZISFROMME as is_from_me,
                    m.ZMESSAGESTATUS as status,
                    m.ZMESSAGEERRORSTATUS as error_status,
                    {media_path_col} as media_path,
                    {media_type_col} as media_item_id,
                    {is_del_col} as is_deleted,
                    s.ZCONTACTJID as chat_jid,
                    s.ZPARTNERNAME as partner_name,
                    s.ZSESSIONTYPE as session_type
                FROM ZWAMESSAGE m
                LEFT JOIN ZWACHATSESSION s ON m.ZCHATSESSION = s.Z_PK
                WHERE m.ZTEXT IS NOT NULL OR {media_path_col} IS NOT NULL OR {media_type_col} IS NOT NULL
                ORDER BY m.ZMESSAGEDATE ASC
                """

                cursor.execute(query)
                for row in cursor.fetchall():
                    date_val = row["message_date"]
                    if not date_val:
                        continue

                    # Timestamp conversion
                    dt = mac_absolute_to_datetime(date_val)
                    if not dt:
                        dt = unix_to_datetime(date_val)

                    is_from_me = bool(row["is_from_me"])
                    raw_chat_name = (row["partner_name"] or "").strip()
                    chat_jid = (row["chat_jid"] or "").strip()
                    from_jid = (row["from_jid"] or "").strip()
                    to_jid = (row["to_jid"] or "").strip()

                    is_group = "@g.us" in chat_jid or row["session_type"] == 1

                    # Clean phone number from JID (e.g., 9779841659861@s.whatsapp.net -> +9779841659861)
                    def clean_jid(jid_str):
                        if not jid_str:
                            return ""
                        num_part = jid_str.split("@")[0]
                        return f"+{num_part}" if num_part.isdigit() else num_part

                    from_clean = clean_jid(from_jid)
                    chat_clean = clean_jid(chat_jid)

                    # Resolve sender & recipient
                    if is_from_me:
                        sender = "Me (Device Owner)"
                        recipient = raw_chat_name or chat_clean or "Chat"
                        direction = "Outgoing"
                    else:
                        sender_num = from_clean or chat_clean or "Unknown"
                        sender_name = raw_chat_name
                        if self.contacts_resolver and sender_num:
                            resolved = self.contacts_resolver.resolve_number(sender_num)
                            if resolved and resolved != sender_num:
                                sender_name = resolved
                        sender = sender_name or sender_num
                        recipient = "Me (Device Owner)"
                        direction = "Incoming"

                    chat_display = raw_chat_name or chat_clean or ("Group Chat" if is_group else "Direct Message")

                    # Text and media formatting
                    text = (row["text_content"] or "").strip()
                    media_p = row["media_path"] or ""
                    if not text and media_p:
                        fname = os.path.basename(media_p)
                        text = f"[Media Attachment: {fname}]"
                    elif not text and row["media_item_id"]:
                        text = "[Media Attachment / Photo / Voice Note]"

                    if not text:
                        continue

                    # Deduplication key
                    utc_str = format_datetime_utc(dt)
                    dedup_key = (app_variant, utc_str, sender, text[:60])
                    if dedup_key in seen_keys:
                        continue
                    seen_keys.add(dedup_key)

                    record = {
                        "source": app_variant,
                        "app_variant": app_variant,
                        "msg_id": row["msg_id"],
                        "chat_name": chat_display,
                        "chat_jid": chat_jid,
                        "is_group": is_group,
                        "sender": sender,
                        "sender_jid": from_jid or chat_jid,
                        "recipient": recipient,
                        "direction": direction,
                        "is_from_me": is_from_me,
                        "is_deleted": bool(row["is_deleted"]),
                        "text": text,
                        "timestamp_utc": utc_str,
                        "timestamp_local": format_datetime_local(dt),
                        "raw_datetime": dt
                    }
                    all_records.append(record)

                conn.close()
            except Exception:
                pass

        all_records.sort(key=lambda r: r.get("timestamp_utc", ""))
        self.messages = all_records
        return self.messages
