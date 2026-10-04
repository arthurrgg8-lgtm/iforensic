import sqlite3
import os
from core.time_utils import mac_absolute_to_datetime, unix_to_datetime, format_datetime_utc, format_datetime_local
from core.db_utils import connect_readonly_sqlite

def format_duration(seconds):
    if seconds is None or seconds == 0:
        return "0s (Unanswered)"
    try:
        s = int(round(float(seconds)))
        if s < 60:
            return f"{s}s"
        m = s // 60
        rem_s = s % 60
        if m < 60:
            return f"{m}m {rem_s:02d}s"
        h = m // 60
        rem_m = m % 60
        return f"{h}h {rem_m:02d}m {rem_s:02d}s"
    except (ValueError, TypeError):
        return str(seconds)

class CallsParser:
    """
    Parses iOS CallHistory.storedata (ZCALLRECORD table).
    Extracts call duration, direction (incoming, outgoing, missed), service provider, and timestamps.
    """

    CALL_TYPES = {
        1: "Incoming (Answered)",
        2: "Outgoing",
        3: "Missed",
        4: "Voicemail",
        5: "Rejected",
        8: "Blocked",
        16: "FaceTime Audio",
        32: "FaceTime Video"
    }

    def __init__(self, db_path):
        self.db_path = db_path
        self.calls = []

    def parse(self):
        if not self.db_path or not os.path.exists(self.db_path):
            return []

        try:
            conn = connect_readonly_sqlite(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            query = """
            SELECT 
                Z_PK,
                ZADDRESS,
                ZDURATION,
                ZDATE,
                ZORIGINATED,
                ZCALLTYPE,
                ZSERVICE_PROVIDER,
                ZLOCATION,
                ZANSWERED,
                ZNAME
            FROM ZCALLRECORD
            ORDER BY ZDATE ASC
            """
            cursor.execute(query)
            for row in cursor.fetchall():
                # ZDATE in CallHistory is Mac Absolute Time (Cocoa 2001) or Unix time
                date_val = row["ZDATE"]
                dt = mac_absolute_to_datetime(date_val)
                if not dt:
                    dt = unix_to_datetime(date_val)

                is_originated = bool(row["ZORIGINATED"])
                is_answered = bool(row["ZANSWERED"])
                duration_sec = row["ZDURATION"] or 0

                if is_originated:
                    call_status = "Outgoing"
                elif is_answered or duration_sec > 0:
                    call_status = "Incoming (Answered)"
                else:
                    call_status = "Missed / Unanswered"

                record = {
                    "record_id": row["Z_PK"],
                    "number": row["ZADDRESS"] or "Unknown",
                    "contact_name": row["ZNAME"] or "Unknown",
                    "duration_seconds": round(float(duration_sec), 2) if duration_sec else 0,
                    "duration_formatted": format_duration(duration_sec),
                    "status": call_status,
                    "service_provider": row["ZSERVICE_PROVIDER"] or "Telephony",
                    "location": row["ZLOCATION"] or "",
                    "timestamp_utc": format_datetime_utc(dt),
                    "timestamp_local": format_datetime_local(dt),
                    "raw_datetime": dt
                }
                self.calls.append(record)

            conn.close()
        except Exception:
            pass

        return self.calls
