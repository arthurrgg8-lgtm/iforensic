import sqlite3
import os
import re
from core.time_utils import mac_absolute_to_datetime, unix_to_datetime, format_datetime_utc, format_datetime_local
from core.db_utils import connect_readonly_sqlite
from parsers.calls_parser import format_duration

def format_file_size(size_bytes):
    if not size_bytes or size_bytes <= 0:
        return ""
    try:
        b = float(size_bytes)
        if b < 1024:
            return f"{int(b)} B"
        elif b < 1024 * 1024:
            return f"{b / 1024:.1f} KB"
        else:
            return f"{b / (1024 * 1024):.1f} MB"
    except Exception:
        return ""

class WhatsAppParser:
    """
    Parses WhatsApp (Standard) and WhatsApp Business (WhatsApp SMB) iOS databases (ChatStorage.sqlite).
    Extracts 1-on-1 chats, group chats, sender numbers, contact names, message text,
    system notices, media attachments (Photos, Videos, Voice Notes, Documents), GPS locations,
    and timestamps in pure plain text.
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

                # Check if ZWAMEDIAITEM exists
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ZWAMEDIAITEM'")
                has_media_item_table = bool(cursor.fetchone())

                from_jid_col = "m.ZFROMJID" if "ZFROMJID" in cols else "NULL"
                to_jid_col = "m.ZTOJID" if "ZTOJID" in cols else "NULL"
                media_path_col = "m.ZMEDIALOCALPATH" if "ZMEDIALOCALPATH" in cols else "NULL"
                media_type_col = "m.ZMEDIAITEM" if "ZMEDIAITEM" in cols else "NULL"
                is_del_col = "m.ZISDELETED" if "ZISDELETED" in cols else "0"

                if has_media_item_table:
                    cursor.execute("PRAGMA table_info(ZWAMEDIAITEM)")
                    mi_cols = set(r["name"] for r in cursor.fetchall())
                    mi_path = "mi.ZMEDIALOCALPATH" if "ZMEDIALOCALPATH" in mi_cols else "NULL"
                    mi_dur = "mi.ZMOVIEDURATION" if "ZMOVIEDURATION" in mi_cols else "0"
                    mi_size = "mi.ZFILESIZE" if "ZFILESIZE" in mi_cols else "0"
                    mi_title = "mi.ZTITLE" if "ZTITLE" in mi_cols else "NULL"
                    mi_lat = "mi.ZLATITUDE" if "ZLATITUDE" in mi_cols else "NULL"
                    mi_lon = "mi.ZLONGITUDE" if "ZLONGITUDE" in mi_cols else "NULL"

                    media_join = "LEFT JOIN ZWAMEDIAITEM mi ON m.ZMEDIAITEM = mi.Z_PK"
                    extra_select = f""",
                        {mi_path} as mi_media_path,
                        {mi_dur} as mi_duration,
                        {mi_size} as mi_size,
                        {mi_title} as mi_title,
                        {mi_lat} as mi_latitude,
                        {mi_lon} as mi_longitude
                    """
                else:
                    media_join = ""
                    extra_select = f""",
                        NULL as mi_media_path,
                        0 as mi_duration,
                        0 as mi_size,
                        NULL as mi_title,
                        NULL as mi_latitude,
                        NULL as mi_longitude
                    """

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
                    {extra_select}
                FROM ZWAMESSAGE m
                LEFT JOIN ZWACHATSESSION s ON m.ZCHATSESSION = s.Z_PK
                {media_join}
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

                    # Clean phone number from JID
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

                    # Media Attachment & GPS Location Resolution
                    text = (row["text_content"] or "").strip()
                    media_p = (row["mi_media_path"] or row["media_path"] or "").strip()
                    dur_sec = float(row["mi_duration"] or 0)
                    sz_bytes = int(row["mi_size"] or 0)
                    sz_str = format_file_size(sz_bytes)
                    title = (row["mi_title"] or "").strip()
                    lat = row["mi_latitude"]
                    lon = row["mi_longitude"]

                    media_info_str = ""
                    if lat and lon and (lat != 0 or lon != 0):
                        maps_link = f"https://www.google.com/maps?q={lat:.6f},{lon:.6f}"
                        media_info_str = f"[Shared Location: {lat:.6f}, {lon:.6f} -> {maps_link}]"
                    elif media_p:
                        fname = os.path.basename(media_p)
                        ext = os.path.splitext(fname)[1].lower()
                        meta_details = []
                        if dur_sec > 0:
                            meta_details.append(format_duration(dur_sec))
                        if sz_str:
                            meta_details.append(sz_str)
                        detail_str = f" ({', '.join(meta_details)})" if meta_details else ""

                        if ext in ('.mp4', '.mov', '.3gp'):
                            media_info_str = f"[Video: {fname}{detail_str}]"
                        elif ext in ('.opus', '.m4a', '.aac', '.mp3', '.wav'):
                            media_info_str = f"[Voice Note / Audio: {fname}{detail_str}]"
                        elif ext in ('.jpg', '.jpeg', '.png', '.heic', '.webp'):
                            media_info_str = f"[Photo: {fname}{detail_str}]"
                        elif ext in ('.pdf', '.docx', '.xlsx', '.zip', '.vcf'):
                            media_info_str = f"[Document: {fname}{detail_str}]"
                        else:
                            media_info_str = f"[Media Attachment: {fname}{detail_str}]"
                    elif row["media_item_id"]:
                        media_info_str = f"[Media Attachment: {title or 'Photo / Video / Audio'}]"

                    # Combine text and media
                    if text and media_info_str:
                        display_text = f"{text} {media_info_str}"
                    elif media_info_str:
                        display_text = media_info_str
                    elif text:
                        display_text = text
                    else:
                        continue

                    # Deduplication key
                    utc_str = format_datetime_utc(dt)
                    dedup_key = (app_variant, utc_str, sender, display_text[:60])
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
                        "text": display_text,
                        "raw_text": text,
                        "media_path": media_p,
                        "media_filename": os.path.basename(media_p) if media_p else "",
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
