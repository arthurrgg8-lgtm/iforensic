import sqlite3
import os
from collections import Counter, defaultdict
from core.time_utils import mac_absolute_to_datetime, unix_to_datetime, format_datetime_utc, format_datetime_local
from core.db_utils import connect_readonly_sqlite

def format_duration(seconds):
    """
    Formats duration in seconds into human-readable text (e.g. '2m 45s', '1h 05m 12s', '0s (Unanswered)').
    """
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

def format_duration_hms(seconds):
    """
    Formats duration into HH:MM:SS format.
    """
    if seconds is None or seconds == 0:
        return "00:00:00"
    try:
        s = int(round(float(seconds)))
        h = s // 3600
        m = (s % 3600) // 60
        sec = s % 60
        return f"{h:02d}:{m:02d}:{sec:02d}"
    except (ValueError, TypeError):
        return "00:00:00"

class CallsParser:
    """
    Parses iOS CallHistory.storedata (ZCALLRECORD table).
    Extracts call frequency, exact duration, in/out direction, service provider, and timestamps.
    Computes comprehensive communication frequency analytics and contact ranking.
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

    def __init__(self, db_path, contacts_resolver=None):
        self.db_path = db_path
        self.contacts_resolver = contacts_resolver
        self.calls = []
        self.frequency_analytics = {}

    def parse(self):
        if not self.db_path or not os.path.exists(self.db_path):
            return []

        try:
            conn = connect_readonly_sqlite(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Check available columns in ZCALLRECORD
            cursor.execute("PRAGMA table_info(ZCALLRECORD)")
            cols = set(r["name"] for r in cursor.fetchall())

            # Build query with fallback for optional columns
            addr_col = "ZADDRESS" if "ZADDRESS" in cols else "NULL"
            dur_col = "ZDURATION" if "ZDURATION" in cols else "0"
            date_col = "ZDATE" if "ZDATE" in cols else "0"
            orig_col = "ZORIGINATED" if "ZORIGINATED" in cols else "0"
            calltype_col = "ZCALLTYPE" if "ZCALLTYPE" in cols else "0"
            prov_col = "ZSERVICE_PROVIDER" if "ZSERVICE_PROVIDER" in cols else "NULL"
            loc_col = "ZLOCATION" if "ZLOCATION" in cols else "NULL"
            ans_col = "ZANSWERED" if "ZANSWERED" in cols else "0"
            name_col = "ZNAME" if "ZNAME" in cols else "NULL"
            handle_col = "ZHANDLE_TYPE" if "ZHANDLE_TYPE" in cols else "NULL"
            disc_col = "ZDISCONNECTED_CAUSE" if "ZDISCONNECTED_CAUSE" in cols else "NULL"

            query = f"""
            SELECT 
                Z_PK as record_id,
                {addr_col} as raw_address,
                {dur_col} as duration_raw,
                {date_col} as date_raw,
                {orig_col} as is_originated,
                {calltype_col} as call_type_id,
                {prov_col} as service_provider,
                {loc_col} as location,
                {ans_col} as is_answered,
                {name_col} as contact_name,
                {handle_col} as handle_type,
                {disc_col} as disconnected_cause
            FROM ZCALLRECORD
            ORDER BY {date_col} ASC
            """

            cursor.execute(query)
            for row in cursor.fetchall():
                date_val = row["date_raw"]
                if not date_val:
                    continue

                # ZDATE in CallHistory is Mac Absolute Time (Cocoa 2001) or Unix timestamp
                dt = mac_absolute_to_datetime(date_val)
                if not dt:
                    dt = unix_to_datetime(date_val)

                is_orig = bool(row["is_originated"])
                is_ans = bool(row["is_answered"])
                dur_sec = float(row["duration_raw"] or 0)
                call_type_id = int(row["call_type_id"] or 0)
                raw_addr = (row["raw_address"] or "").strip()
                raw_name = (row["contact_name"] or "").strip()
                provider = (row["service_provider"] or "").strip()

                # Determine Service Provider & Protocol
                if "FaceTime" in provider or call_type_id in (16, 32):
                    service_display = "FaceTime Video" if call_type_id == 32 else "FaceTime Audio"
                elif "WhatsApp" in provider:
                    service_display = "WhatsApp Audio"
                elif "viber" in provider.lower():
                    service_display = "Viber Call"
                elif "skype" in provider.lower():
                    service_display = "Skype Call"
                elif provider:
                    service_display = provider
                else:
                    service_display = "Telephony (Cellular)"

                # Determine Direction & Detailed Status
                if is_orig:
                    direction_category = "OUTGOING"
                    status = "Outgoing (Answered)" if (dur_sec > 0 or is_ans) else "Outgoing (Unanswered)"
                else:
                    if dur_sec > 0 or is_ans:
                        direction_category = "INCOMING"
                        status = "Incoming (Answered)"
                    elif call_type_id == 8:
                        direction_category = "BLOCKED"
                        status = "Blocked Call"
                    elif call_type_id == 5:
                        direction_category = "REJECTED"
                        status = "Rejected Call"
                    elif call_type_id == 4:
                        direction_category = "VOICEMAIL"
                        status = "Voicemail"
                    else:
                        direction_category = "MISSED"
                        status = "Missed / Unanswered"

                # Contact Name Resolution
                display_name = raw_name if (raw_name and raw_name != "Unknown") else "Unknown"
                if display_name == "Unknown" and raw_addr and self.contacts_resolver:
                    resolved = self.contacts_resolver.resolve_number(raw_addr)
                    if resolved and resolved != raw_addr:
                        display_name = resolved

                record = {
                    "record_id": row["record_id"],
                    "number": raw_addr or "Unknown",
                    "contact_name": display_name,
                    "direction": direction_category,
                    "status": status,
                    "call_type_id": call_type_id,
                    "call_type_label": self.CALL_TYPES.get(call_type_id, status),
                    "duration_seconds": round(dur_sec, 2),
                    "duration_formatted": format_duration(dur_sec),
                    "duration_hms": format_duration_hms(dur_sec),
                    "service_provider": service_display,
                    "location": row["location"] or "",
                    "timestamp_utc": format_datetime_utc(dt),
                    "timestamp_local": format_datetime_local(dt),
                    "hour_of_day": dt.hour if dt else 0,
                    "day_of_week": dt.strftime("%A") if dt else "Unknown",
                    "raw_datetime": dt
                }
                self.calls.append(record)

            conn.close()
        except Exception:
            pass

        self._compute_frequency_analytics()
        return self.calls

    def _compute_frequency_analytics(self):
        """
        Computes detailed call frequency, top communication partners, talk time totals,
        and temporal distribution.
        """
        if not self.calls:
            self.frequency_analytics = {
                "total_calls": 0,
                "total_incoming": 0,
                "total_outgoing": 0,
                "total_missed": 0,
                "total_duration_seconds": 0,
                "total_duration_formatted": "0s",
                "inbound_duration_seconds": 0,
                "inbound_duration_formatted": "0s",
                "outbound_duration_seconds": 0,
                "outbound_duration_formatted": "0s",
                "average_duration_seconds": 0,
                "average_duration_formatted": "0s",
                "frequent_contacts": [],
                "peak_hours": [],
                "peak_weekdays": []
            }
            return self.frequency_analytics

        total_calls = len(self.calls)
        total_dur = sum(c.get("duration_seconds", 0) for c in self.calls)
        inbound_dur = sum(c.get("duration_seconds", 0) for c in self.calls if c.get("direction") == "INCOMING")
        outbound_dur = sum(c.get("duration_seconds", 0) for c in self.calls if c.get("direction") == "OUTGOING")

        inc_count = sum(1 for c in self.calls if c.get("direction") == "INCOMING")
        out_count = sum(1 for c in self.calls if c.get("direction") == "OUTGOING")
        missed_count = sum(1 for c in self.calls if c.get("direction") in ("MISSED", "BLOCKED", "REJECTED"))

        # Per-Contact & Per-Number Aggregations
        contact_stats = defaultdict(lambda: {
            "contact_name": "Unknown",
            "number": "Unknown",
            "total_calls": 0,
            "incoming_count": 0,
            "outgoing_count": 0,
            "missed_count": 0,
            "total_duration_seconds": 0.0,
            "first_call_utc": None,
            "last_call_utc": None,
            "first_call_local": None,
            "last_call_local": None,
        })

        hour_counter = Counter()
        day_counter = Counter()

        for c in self.calls:
            actor_key = c.get("number") or c.get("contact_name") or "Unknown"
            stat = contact_stats[actor_key]
            
            if stat["contact_name"] == "Unknown" and c.get("contact_name") != "Unknown":
                stat["contact_name"] = c.get("contact_name")
            if stat["number"] == "Unknown" and c.get("number") != "Unknown":
                stat["number"] = c.get("number")

            stat["total_calls"] += 1
            direction = c.get("direction", "UNKNOWN")
            if direction == "INCOMING":
                stat["incoming_count"] += 1
            elif direction == "OUTGOING":
                stat["outgoing_count"] += 1
            else:
                stat["missed_count"] += 1

            stat["total_duration_seconds"] += c.get("duration_seconds", 0)

            ts_utc = c.get("timestamp_utc")
            ts_loc = c.get("timestamp_local")
            if ts_utc:
                if not stat["first_call_utc"] or ts_utc < stat["first_call_utc"]:
                    stat["first_call_utc"] = ts_utc
                    stat["first_call_local"] = ts_loc
                if not stat["last_call_utc"] or ts_utc > stat["last_call_utc"]:
                    stat["last_call_utc"] = ts_utc
                    stat["last_call_local"] = ts_loc

            hour_counter[c.get("hour_of_day", 0)] += 1
            day_counter[c.get("day_of_week", "Unknown")] += 1

        ranked_contacts = []
        for key, s in contact_stats.items():
            tot = s["total_calls"]
            dur = s["total_duration_seconds"]
            avg_d = round(dur / tot, 2) if tot > 0 else 0
            
            display_actor = s["contact_name"] if s["contact_name"] != "Unknown" else s["number"]
            ranked_contacts.append({
                "contact_name": s["contact_name"],
                "number": s["number"],
                "display_actor": display_actor,
                "total_calls": tot,
                "incoming_count": s["incoming_count"],
                "outgoing_count": s["outgoing_count"],
                "missed_count": s["missed_count"],
                "ratio_summary": f"{s['incoming_count']} In / {s['outgoing_count']} Out / {s['missed_count']} Missed",
                "total_duration_seconds": round(dur, 2),
                "total_duration_formatted": format_duration(dur),
                "total_duration_hms": format_duration_hms(dur),
                "avg_duration_seconds": avg_d,
                "avg_duration_formatted": format_duration(avg_d),
                "first_call_local": s["first_call_local"] or "N/A",
                "last_call_local": s["last_call_local"] or "N/A",
                "first_call_utc": s["first_call_utc"] or "N/A",
                "last_call_utc": s["last_call_utc"] or "N/A"
            })

        # Rank by total calls descending, then total duration descending
        ranked_contacts.sort(key=lambda x: (x["total_calls"], x["total_duration_seconds"]), reverse=True)

        avg_call_dur = round(total_dur / total_calls, 2) if total_calls > 0 else 0

        self.frequency_analytics = {
            "total_calls": total_calls,
            "total_incoming": inc_count,
            "total_outgoing": out_count,
            "total_missed": missed_count,
            "total_duration_seconds": round(total_dur, 2),
            "total_duration_formatted": format_duration(total_dur),
            "total_duration_hms": format_duration_hms(total_dur),
            "inbound_duration_seconds": round(inbound_dur, 2),
            "inbound_duration_formatted": format_duration(inbound_dur),
            "outbound_duration_seconds": round(outbound_dur, 2),
            "outbound_duration_formatted": format_duration(outbound_dur),
            "average_duration_seconds": avg_call_dur,
            "average_duration_formatted": format_duration(avg_call_dur),
            "frequent_contacts": ranked_contacts,
            "peak_hours": hour_counter.most_common(5),
            "peak_weekdays": day_counter.most_common(7)
        }
        return self.frequency_analytics

    def get_frequency_analytics(self):
        if not self.frequency_analytics:
            self._compute_frequency_analytics()
        return self.frequency_analytics
