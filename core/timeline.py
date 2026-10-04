class TimelineEngine:
    """
    Synthesizes messages, call logs, notes, web history, photos, and financial transactions
    into a unified, normalized chronological sequence.
    """

    def __init__(self):
        self.events = []

    def ingest_sms(self, messages):
        for m in messages:
            if m.get("raw_datetime"):
                self.events.append({
                    "timestamp": m["raw_datetime"],
                    "timestamp_local": m.get("timestamp_local", "N/A"),
                    "type": "MESSAGE",
                    "source": m.get("service", "SMS"),
                    "actor": m.get("sender", "Unknown"),
                    "target": m.get("recipient", "Unknown"),
                    "summary": m.get("text", "")[:120],
                    "details": m
                })

    def ingest_calls(self, calls):
        for c in calls:
            if c.get("raw_datetime"):
                self.events.append({
                    "timestamp": c["raw_datetime"],
                    "timestamp_local": c.get("timestamp_local", "N/A"),
                    "type": "CALL",
                    "source": c.get("service_provider", "Telephony"),
                    "actor": c.get("contact_name", c.get("number", "Unknown")),
                    "target": "Device Owner",
                    "summary": f"{c.get('status')} | Duration: {c.get('duration_formatted')} ({c.get('number')})",
                    "details": c
                })

    def ingest_notes(self, notes):
        for n in notes:
            if n.get("raw_datetime"):
                self.events.append({
                    "timestamp": n["raw_datetime"],
                    "timestamp_local": n.get("modified_local", "N/A"),
                    "type": "NOTE",
                    "source": "Apple Notes",
                    "actor": n.get("account", "Local"),
                    "target": n.get("folder", "Notes"),
                    "summary": f"[{n.get('title')}] {n.get('snippet', '')[:80]}",
                    "details": n
                })

    def ingest_safari(self, history):
        for h in history:
            if h.get("raw_datetime"):
                self.events.append({
                    "timestamp": h["raw_datetime"],
                    "timestamp_local": h.get("timestamp_local", "N/A"),
                    "type": "WEB_VISIT",
                    "source": "Safari",
                    "actor": "User",
                    "target": h.get("url", ""),
                    "summary": f"{h.get('title', '')} ({h.get('url', '')})",
                    "details": h
                })

    def ingest_photos(self, photos):
        for p in photos:
            if p.get("raw_datetime"):
                gps_str = f" [GPS: {p.get('latitude'):.4f}, {p.get('longitude'):.4f}]" if p.get("has_gps") else ""
                self.events.append({
                    "timestamp": p["raw_datetime"],
                    "timestamp_local": p.get("timestamp_local", "N/A"),
                    "type": "PHOTO",
                    "source": "Camera / Gallery",
                    "actor": "User",
                    "target": p.get("filename", ""),
                    "summary": f"Photo Taken: {p.get('filename')}{gps_str}",
                    "details": p
                })

    def build_timeline(self, reverse=False):
        """
        Sorts all ingested events by timestamp.
        """
        valid_events = [e for e in self.events if e.get("timestamp")]
        valid_events.sort(key=lambda x: x["timestamp"], reverse=reverse)
        return valid_events
