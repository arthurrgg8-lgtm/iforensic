import os
import sqlite3
import json
from core.time_utils import unix_to_datetime, apple_to_iso, format_datetime_local, format_datetime_utc
from core.db_utils import connect_readonly_sqlite

class EnterpriseAppsParser:
    """
    Parses cached enterprise and modern secure cloud application databases:
    1. Telegram Messenger (tgdata.db / Telegraph)
    2. Signal Private Messenger (signal.sqlite / group.org.whispersystems.signal)
    3. Microsoft Teams (teams.db / com.microsoft.skype.teams)
    4. ProtonMail (protonmail.db / ch.protonmail.protonmail)
    """

    def __init__(self, manifest_resolver=None):
        self.resolver = manifest_resolver
        self.telegram_messages = []
        self.signal_records = []
        self.teams_messages = []
        self.protonmail_records = []

    def parse(self):
        self._parse_telegram()
        self._parse_signal()
        self._parse_teams()
        self._parse_protonmail()

        total = (len(self.telegram_messages) + len(self.signal_records) +
                 len(self.teams_messages) + len(self.protonmail_records))

        return {
            "telegram": self.telegram_messages,
            "signal": self.signal_records,
            "teams": self.teams_messages,
            "protonmail": self.protonmail_records,
            "total_enterprise_records": total
        }

    def _parse_telegram(self):
        if not self.resolver:
            return

        db_path = self.resolver.find_file(
            domain="AppDomain-ph.telegra.Telegraph",
            relative_path="Documents/tgdata.db",
            filename="tgdata.db"
        ) or self.resolver.find_file(filename="telegram.sqlite")

        if not db_path or not os.path.exists(db_path):
            return

        try:
            conn = connect_readonly_sqlite(db_path)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cur.fetchall()]

            # 1. Parse TG Messages
            for tbl in ["messages_v2", "messages", "TGMessage"]:
                if tbl in tables:
                    try:
                        cur.execute(f"SELECT * FROM {tbl} ORDER BY date DESC LIMIT 500")
                        for row in cur.fetchall():
                            d = dict(row)
                            raw_date = d.get("date") or d.get("timestamp") or 0
                            dt_obj = unix_to_datetime(raw_date)
                            self.telegram_messages.append({
                                "source": "Telegram",
                                "id": d.get("id") or d.get("mid"),
                                "timestamp_utc": format_datetime_utc(dt_obj),
                                "timestamp_local": format_datetime_local(dt_obj),
                                "from_id": d.get("from_id") or d.get("sender_id"),
                                "chat_id": d.get("chat_id") or d.get("peer_id"),
                                "text": str(d.get("message") or d.get("text") or d.get("data") or "")[:300],
                                "media_type": d.get("media_type") or "text"
                            })
                        break
                    except Exception:
                        pass

            conn.close()
        except Exception:
            pass

    def _parse_signal(self):
        if not self.resolver:
            return

        db_path = self.resolver.find_file(
            domain="AppDomainGroup-group.org.whispersystems.signal",
            relative_path="Documents/signal.sqlite",
            filename="signal.sqlite"
        )

        if not db_path or not os.path.exists(db_path):
            return

        try:
            conn = connect_readonly_sqlite(db_path)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cur.fetchall()]

            # Parse Signal Recipients / Accounts if table exists
            for tbl in ["recipient", "SignalRecipient", "account"]:
                if tbl in tables:
                    try:
                        cur.execute(f"SELECT * FROM {tbl} LIMIT 200")
                        for row in cur.fetchall():
                            d = dict(row)
                            self.signal_records.append({
                                "source": "Signal Metadata",
                                "id": d.get("id") or d.get("uuid") or "N/A",
                                "phone": d.get("phone") or d.get("e164") or "N/A",
                                "name": d.get("profileName") or d.get("fullName") or "Signal User",
                                "about": d.get("profileAbout") or ""
                            })
                        break
                    except Exception:
                        pass
            conn.close()
        except Exception:
            pass

    def _parse_teams(self):
        if not self.resolver:
            return

        db_path = self.resolver.find_file(
            domain="AppDomain-com.microsoft.skype.teams",
            relative_path="Library/Application Support/teams.db",
            filename="teams.db"
        )

        if not db_path or not os.path.exists(db_path):
            return

        try:
            conn = connect_readonly_sqlite(db_path)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cur.fetchall()]

            for tbl in ["chat_messages", "messages", "teams_chat"]:
                if tbl in tables:
                    try:
                        cur.execute(f"SELECT * FROM {tbl} ORDER BY timestamp DESC LIMIT 300")
                        for row in cur.fetchall():
                            d = dict(row)
                            ts = d.get("timestamp") or d.get("created_time") or 0
                            dt_obj = unix_to_datetime(ts)
                            self.teams_messages.append({
                                "source": "Microsoft Teams",
                                "sender": d.get("sender_name") or d.get("sender_id") or "Teams User",
                                "channel": d.get("channel_name") or d.get("conversation_id") or "Direct Chat",
                                "timestamp_utc": format_datetime_utc(dt_obj),
                                "timestamp_local": format_datetime_local(dt_obj),
                                "text": str(d.get("content") or d.get("body") or "")[:300]
                            })
                        break
                    except Exception:
                        pass
            conn.close()
        except Exception:
            pass

    def _parse_protonmail(self):
        if not self.resolver:
            return

        db_path = self.resolver.find_file(
            domain="AppDomain-ch.protonmail.protonmail",
            relative_path="Documents/protonmail.db",
            filename="protonmail.db"
        )

        if not db_path or not os.path.exists(db_path):
            return

        try:
            conn = connect_readonly_sqlite(db_path)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cur.fetchall()]

            for tbl in ["messages", "cached_emails", "headers"]:
                if tbl in tables:
                    try:
                        cur.execute(f"SELECT * FROM {tbl} LIMIT 200")
                        for row in cur.fetchall():
                            d = dict(row)
                            ts = d.get("time") or d.get("timestamp") or 0
                            dt_obj = unix_to_datetime(ts)
                            self.protonmail_records.append({
                                "source": "ProtonMail",
                                "sender": d.get("sender") or d.get("from") or "Proton User",
                                "recipient": d.get("recipient") or d.get("to") or "N/A",
                                "subject": d.get("subject") or d.get("title") or "[Encrypted Subject]",
                                "timestamp_utc": format_datetime_utc(dt_obj),
                                "timestamp_local": format_datetime_local(dt_obj)
                            })
                        break
                    except Exception:
                        pass
            conn.close()
        except Exception:
            pass
