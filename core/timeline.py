import datetime
from datetime import timezone
from core.time_utils import to_datetime

class TimelineEngine:
    """
    Enterprise Chronological Timeline Engine.
    Synthesizes messages (SMS, iMessage, WhatsApp, Telegram, Signal, Teams),
    call records, voicemails, voice memos, notes, web history, photos, and financial transactions
    into a unified, timezone-normalized master forensic sequence.
    """

    def __init__(self):
        self.events = []

    def _normalize_timestamp(self, ts):
        if not ts:
            return None
        return to_datetime(ts)

    def ingest_sms(self, messages):
        for m in (messages or []):
            dt = self._normalize_timestamp(m.get("raw_datetime") or m.get("timestamp_utc"))
            if dt:
                self.events.append({
                    "timestamp": dt,
                    "timestamp_local": m.get("timestamp_local", "N/A"),
                    "type": "MESSAGE",
                    "source": m.get("service", "SMS / iMessage"),
                    "actor": m.get("sender", "Unknown"),
                    "target": m.get("recipient", "Unknown"),
                    "summary": (m.get("text") or "")[:150],
                    "details": m
                })

    def ingest_calls(self, calls):
        for c in (calls or []):
            dt = self._normalize_timestamp(c.get("raw_datetime") or c.get("timestamp_utc"))
            if dt:
                self.events.append({
                    "timestamp": dt,
                    "timestamp_local": c.get("timestamp_local", "N/A"),
                    "type": "CALL",
                    "source": c.get("service_provider", "Telephony"),
                    "actor": c.get("contact_name") or c.get("number", "Unknown"),
                    "target": "Device Owner",
                    "summary": f"{c.get('status')} | Duration: {c.get('duration_formatted')} ({c.get('number')})",
                    "details": c
                })

    def ingest_notes(self, notes):
        for n in (notes or []):
            dt = self._normalize_timestamp(n.get("raw_datetime") or n.get("modified_utc") or n.get("created_utc"))
            if dt:
                self.events.append({
                    "timestamp": dt,
                    "timestamp_local": n.get("modified_local", "N/A"),
                    "type": "NOTE",
                    "source": "Apple Notes",
                    "actor": n.get("account", "Local"),
                    "target": n.get("folder", "Notes"),
                    "summary": f"[{n.get('title')}] {(n.get('snippet') or n.get('full_content') or '')[:100]}",
                    "details": n
                })

    def ingest_safari(self, history):
        for h in (history or []):
            dt = self._normalize_timestamp(h.get("raw_datetime") or h.get("timestamp_utc"))
            if dt:
                self.events.append({
                    "timestamp": dt,
                    "timestamp_local": h.get("timestamp_local", "N/A"),
                    "type": "WEB_VISIT",
                    "source": "Safari",
                    "actor": "User",
                    "target": h.get("url", ""),
                    "summary": f"{h.get('title', '')} ({h.get('url', '')})",
                    "details": h
                })

    def ingest_photos(self, photos):
        for p in (photos or []):
            dt = self._normalize_timestamp(p.get("raw_datetime") or p.get("timestamp_created_utc") or p.get("timestamp_utc"))
            if dt:
                gps_str = f" [GPS: {p.get('latitude'):.4f}, {p.get('longitude'):.4f}]" if p.get("has_gps") and p.get("latitude") and p.get("longitude") else ""
                self.events.append({
                    "timestamp": dt,
                    "timestamp_local": p.get("timestamp_created_local") or p.get("timestamp_local", "N/A"),
                    "type": "PHOTO",
                    "source": "Camera Roll / Media",
                    "actor": "User",
                    "target": p.get("filename", ""),
                    "summary": f"Photo/Video: {p.get('filename')} ({p.get('media_type', 'Photo')}){gps_str}",
                    "details": p
                })

    def ingest_whatsapp(self, whatsapp_messages):
        for m in (whatsapp_messages or []):
            dt = self._normalize_timestamp(m.get("raw_datetime") or m.get("timestamp_utc"))
            if dt:
                variant = m.get("app_variant", "WhatsApp")
                self.events.append({
                    "timestamp": dt,
                    "timestamp_local": m.get("timestamp_local", "N/A"),
                    "type": "CHAT",
                    "source": variant,
                    "actor": m.get("sender", "Unknown"),
                    "target": m.get("recipient", "Unknown"),
                    "summary": f"[{m.get('chat_name', 'Chat')}] {(m.get('text') or '')[:150]}",
                    "details": m
                })

    def ingest_financial(self, transactions):
        for f in (transactions or []):
            dt = self._normalize_timestamp(f.get("raw_datetime") or f.get("timestamp_utc"))
            if dt:
                self.events.append({
                    "timestamp": dt,
                    "timestamp_local": f.get("timestamp_local", "N/A"),
                    "type": "FINANCIAL",
                    "source": f.get("source", "Financial Ledger"),
                    "actor": f.get("entity", "Bank / Financial Service"),
                    "target": "Device Owner",
                    "summary": f"[{f.get('type')}] Amount: {f.get('amount', 'N/A')} | {f.get('summary', '')[:100]}",
                    "details": f
                })

    def ingest_recordings(self, recordings_dict):
        if not recordings_dict or not isinstance(recordings_dict, dict):
            return
        # Voice Memos
        for r in recordings_dict.get("voice_memos", []):
            dt = self._normalize_timestamp(r.get("timestamp_utc"))
            if dt:
                self.events.append({
                    "timestamp": dt,
                    "timestamp_local": r.get("timestamp_local", "N/A"),
                    "type": "VOICE_MEMO",
                    "source": "Voice Memos",
                    "actor": "User",
                    "target": r.get("title", "Voice Memo"),
                    "summary": f"Voice Memo: {r.get('title')} ({r.get('duration_seconds', 0)}s)",
                    "details": r
                })
        # Voicemails
        for v in recordings_dict.get("voicemails", []):
            dt = self._normalize_timestamp(v.get("timestamp_utc"))
            if dt:
                self.events.append({
                    "timestamp": dt,
                    "timestamp_local": v.get("timestamp_local", "N/A"),
                    "type": "VOICEMAIL",
                    "source": "Voicemail",
                    "actor": v.get("caller_name") or v.get("sender", "Unknown"),
                    "target": "Device Owner",
                    "summary": f"Voicemail from {v.get('caller_name')} ({v.get('duration_seconds', 0)}s): {(v.get('transcription') or '')[:100]}",
                    "details": v
                })

    def ingest_enterprise_apps(self, enterprise_data):
        if not enterprise_data:
            return
        all_msgs = []
        if isinstance(enterprise_data, dict):
            all_msgs = enterprise_data.get("all_third_party_messages", [])
            if not all_msgs:
                for k, v in enterprise_data.items():
                    if isinstance(v, list) and k not in ("viber_calls", "total_enterprise_records"):
                        all_msgs.extend(v)
        elif isinstance(enterprise_data, list):
            all_msgs = enterprise_data

        for em in all_msgs:
            dt = self._normalize_timestamp(em.get("raw_datetime") or em.get("timestamp_utc"))
            if dt:
                app_name = em.get("app") or em.get("source", "Third-Party App")
                self.events.append({
                    "timestamp": dt,
                    "timestamp_local": em.get("timestamp_local", "N/A"),
                    "type": "APP_MSG",
                    "source": app_name,
                    "actor": em.get("sender", "Unknown"),
                    "target": em.get("recipient") or em.get("chat_name", "Chat"),
                    "summary": f"[{app_name}] {(em.get('text') or '')[:150]}",
                    "details": em
                })

    def build_timeline(self, reverse=False):
        """
        Sorts all ingested events by timezone-normalized UTC timestamp.
        Guarantees no comparison crashes between offset-naive and offset-aware datetimes.
        """
        valid_events = []
        for e in self.events:
            ts = e.get("timestamp")
            if ts and isinstance(ts, datetime.datetime):
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                else:
                    ts = ts.astimezone(timezone.utc)
                e["timestamp"] = ts
                valid_events.append(e)

        valid_events.sort(key=lambda x: x["timestamp"], reverse=reverse)
        return valid_events
