import os
import sqlite3
import json
from core.time_utils import (
    to_datetime,
    unix_to_datetime,
    mac_absolute_to_datetime,
    parse_any_time,
    format_datetime_local,
    format_datetime_utc
)
from core.db_utils import connect_readonly_sqlite

class EnterpriseAppsParser:
    """
    Comprehensive Third-Party & Social Apps Forensic Parser.
    Extracts chat messages, calls, media metadata, and account identities from:
    1. Facebook Messenger (Meta Lightspeed & Legacy SQLite)
    2. Telegram Messenger (Telegraph / Telegram-iOS)
    3. Viber (Rakuten Viber Chats & Call Records)
    4. Signal Private Messenger (WhisperSystems)
    5. Instagram Direct (Meta Instagram)
    6. Microsoft Teams (SkypeTeams)
    7. Discord
    8. Skype
    9. Line
    10. WeChat
    11. ProtonMail
    12. Heuristic Universal App Scanner (discovers any unlisted third-party messaging DBs)
    """

    def __init__(self, manifest_resolver=None, contacts_resolver=None):
        self.resolver = manifest_resolver
        self.contacts_resolver = contacts_resolver
        self.messenger_messages = []
        self.telegram_messages = []
        self.viber_messages = []
        self.viber_calls = []
        self.signal_records = []
        self.instagram_messages = []
        self.teams_messages = []
        self.discord_messages = []
        self.skype_messages = []
        self.line_messages = []
        self.wechat_messages = []
        self.protonmail_records = []
        self.generic_third_party_messages = []
        self.all_messages = []

    def parse(self):
        if not self.resolver:
            return self._build_result_dict()

        self._parse_messenger()
        self._parse_telegram()
        self._parse_viber()
        self._parse_signal()
        self._parse_instagram()
        self._parse_teams()
        self._parse_discord()
        self._parse_skype()
        self._parse_line()
        self._parse_wechat()
        self._parse_protonmail()
        self._parse_heuristic_third_party_apps()

        # Combine all third party messages into a unified list
        combined = []
        combined.extend(self.messenger_messages)
        combined.extend(self.telegram_messages)
        combined.extend(self.viber_messages)
        combined.extend(self.instagram_messages)
        combined.extend(self.teams_messages)
        combined.extend(self.discord_messages)
        combined.extend(self.skype_messages)
        combined.extend(self.line_messages)
        combined.extend(self.wechat_messages)
        combined.extend(self.generic_third_party_messages)

        # Sort chronologically
        combined.sort(key=lambda x: x.get("timestamp_utc", ""))
        self.all_messages = combined

        return self._build_result_dict()

    def _build_result_dict(self):
        total = (
            len(self.messenger_messages) +
            len(self.telegram_messages) +
            len(self.viber_messages) +
            len(self.viber_calls) +
            len(self.signal_records) +
            len(self.instagram_messages) +
            len(self.teams_messages) +
            len(self.discord_messages) +
            len(self.skype_messages) +
            len(self.line_messages) +
            len(self.wechat_messages) +
            len(self.protonmail_records) +
            len(self.generic_third_party_messages)
        )
        return {
            "messenger": self.messenger_messages,
            "telegram": self.telegram_messages,
            "viber": self.viber_messages,
            "viber_calls": self.viber_calls,
            "signal": self.signal_records,
            "instagram": self.instagram_messages,
            "teams": self.teams_messages,
            "discord": self.discord_messages,
            "skype": self.skype_messages,
            "line": self.line_messages,
            "wechat": self.wechat_messages,
            "protonmail": self.protonmail_records,
            "generic_apps": self.generic_third_party_messages,
            "all_third_party_messages": self.all_messages,
            "total_enterprise_records": total
        }

    def _convert_timestamp(self, val):
        if not val:
            return None
        return to_datetime(val)

    def _parse_messenger(self):
        """
        Parses Facebook Messenger databases (Meta Lightspeed: lightspeed.db, threads.db, orca.sqlite, messenger.sqlite).
        """
        db_candidates = self.resolver.find_all_files(domain_contains="Messenger") + \
                        self.resolver.find_all_files(filename="lightspeed.db") + \
                        self.resolver.find_all_files(filename="threads.db") + \
                        self.resolver.find_all_files(filename="orca.sqlite") + \
                        self.resolver.find_all_files(filename="messenger.sqlite") + \
                        self.resolver.find_all_files(filename="LSDatabase.sqlite")
        
        seen_dbs = set()
        for db_p in db_candidates:
            if not db_p or db_p in seen_dbs or not os.path.exists(db_p):
                continue
            seen_dbs.add(db_p)

            try:
                conn = connect_readonly_sqlite(db_p)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = set(row[0] for row in cur.fetchall())

                # Thread mapping
                threads_map = {}
                for t_tbl in ["threads", "threads_v2", "thread_info"]:
                    if t_tbl in tables:
                        try:
                            cur.execute(f"SELECT * FROM {t_tbl}")
                            for r in cur.fetchall():
                                d = dict(r)
                                tid = d.get("thread_key") or d.get("thread_id") or d.get("id")
                                name = d.get("thread_name") or d.get("name") or d.get("snippet")
                                if tid and name:
                                    threads_map[str(tid)] = str(name)
                        except Exception:
                            pass

                # Message extraction
                for m_tbl in ["messages", "messages_v2", "threads_messages"]:
                    if m_tbl in tables:
                        try:
                            cur.execute(f"SELECT * FROM {m_tbl}")
                            for row in cur.fetchall():
                                d = dict(row)
                                text = d.get("text") or d.get("body") or d.get("snippet") or d.get("content")
                                if not text:
                                    continue
                                ts_raw = d.get("timestamp_ms") or d.get("timestamp") or d.get("date") or d.get("time")
                                dt = self._convert_timestamp(ts_raw)
                                sender_id = str(d.get("sender_id") or d.get("user_id") or d.get("author_id") or "Unknown")
                                thread_id = str(d.get("thread_key") or d.get("thread_id") or "Direct Chat")
                                chat_title = threads_map.get(thread_id, thread_id)

                                self.messenger_messages.append({
                                    "source": "Facebook Messenger",
                                    "app": "Facebook Messenger",
                                    "chat_name": chat_title,
                                    "sender": sender_id,
                                    "text": str(text).strip(),
                                    "timestamp_utc": format_datetime_utc(dt) if dt else "N/A",
                                    "timestamp_local": format_datetime_local(dt) if dt else "N/A",
                                    "raw_datetime": dt
                                })
                            break
                        except Exception:
                            pass
                conn.close()
            except Exception:
                pass

    def _parse_telegram(self):
        """
        Parses Telegram Messenger databases (tgdata.db, store.sqlite, account-*.db).
        """
        db_candidates = self.resolver.find_all_files(domain_contains="telegra") + \
                        self.resolver.find_all_files(filename="tgdata.db") + \
                        self.resolver.find_all_files(filename="store.sqlite") + \
                        self.resolver.find_all_files(filename="telegram.sqlite")

        seen_dbs = set()
        for db_p in db_candidates:
            if not db_p or db_p in seen_dbs or not os.path.exists(db_p):
                continue
            seen_dbs.add(db_p)

            try:
                conn = connect_readonly_sqlite(db_p)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = set(row[0] for row in cur.fetchall())

                # User mapping
                user_map = {}
                for u_tbl in ["users", "users_v2", "TGUser"]:
                    if u_tbl in tables:
                        try:
                            cur.execute(f"SELECT * FROM {u_tbl}")
                            for r in cur.fetchall():
                                d = dict(r)
                                uid = d.get("id") or d.get("uid") or d.get("user_id")
                                fname = d.get("first_name") or ""
                                lname = d.get("last_name") or ""
                                uname = d.get("username") or ""
                                full = f"{fname} {lname}".strip() or uname or str(uid)
                                if uid:
                                    user_map[str(uid)] = full
                        except Exception:
                            pass

                # Chat mapping
                chat_map = {}
                for c_tbl in ["chats", "channels", "dialogs", "conversations"]:
                    if c_tbl in tables:
                        try:
                            cur.execute(f"SELECT * FROM {c_tbl}")
                            for r in cur.fetchall():
                                d = dict(r)
                                cid = d.get("id") or d.get("chat_id") or d.get("peer_id")
                                title = d.get("title") or d.get("name") or d.get("username")
                                if cid and title:
                                    chat_map[str(cid)] = str(title)
                        except Exception:
                            pass

                # Messages
                for m_tbl in ["messages_v2", "messages", "TGMessage", "chat_messages"]:
                    if m_tbl in tables:
                        try:
                            cur.execute(f"SELECT * FROM {m_tbl} ORDER BY date DESC LIMIT 2000")
                            for r in cur.fetchall():
                                d = dict(r)
                                text = d.get("message") or d.get("text") or d.get("data")
                                if not text and not d.get("media"):
                                    continue
                                raw_date = d.get("date") or d.get("timestamp") or 0
                                dt = self._convert_timestamp(raw_date)
                                from_id = str(d.get("from_id") or d.get("sender_id") or "Me")
                                chat_id = str(d.get("chat_id") or d.get("peer_id") or "Direct")
                                sender_name = user_map.get(from_id, from_id)
                                chat_name = chat_map.get(chat_id, user_map.get(chat_id, chat_id))

                                self.telegram_messages.append({
                                    "source": "Telegram",
                                    "app": "Telegram",
                                    "id": d.get("id") or d.get("mid"),
                                    "chat_name": chat_name,
                                    "sender": sender_name,
                                    "text": str(text or "[Media Attachment]").strip(),
                                    "timestamp_utc": format_datetime_utc(dt) if dt else "N/A",
                                    "timestamp_local": format_datetime_local(dt) if dt else "N/A",
                                    "raw_datetime": dt
                                })
                            break
                        except Exception:
                            pass
                conn.close()
            except Exception:
                pass

    def _parse_viber(self):
        """
        Parses Rakuten Viber databases (Contacts.data, Viber.sqlite, viber.db, Messages.data).
        Extracts both chat messages and Viber VoIP call logs.
        """
        db_candidates = self.resolver.find_all_files(domain_contains="viber") + \
                        self.resolver.find_all_files(filename="Contacts.data") + \
                        self.resolver.find_all_files(filename="Viber.sqlite") + \
                        self.resolver.find_all_files(filename="viber.db") + \
                        self.resolver.find_all_files(filename="Messages.data")

        seen_dbs = set()
        for db_p in db_candidates:
            if not db_p or db_p in seen_dbs or not os.path.exists(db_p):
                continue
            seen_dbs.add(db_p)

            try:
                conn = connect_readonly_sqlite(db_p)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = set(row[0] for row in cur.fetchall())

                # Viber Contacts
                viber_contacts = {}
                for c_tbl in ["ZCONTACT", "ZPHONENUMBERINDEX", "contacts"]:
                    if c_tbl in tables:
                        try:
                            cur.execute(f"SELECT * FROM {c_tbl}")
                            for r in cur.fetchall():
                                d = dict(r)
                                num = d.get("ZPHONENUMBER") or d.get("phone_number") or d.get("number")
                                name = d.get("ZDISPLAYNAME") or d.get("display_name") or d.get("name")
                                if num and name:
                                    viber_contacts[str(num)] = str(name)
                        except Exception:
                            pass

                # Viber Messages
                for m_tbl in ["ZMESSAGE", "messages", "ViberMessage"]:
                    if m_tbl in tables:
                        try:
                            cur.execute(f"SELECT * FROM {m_tbl}")
                            for r in cur.fetchall():
                                d = dict(r)
                                text = d.get("ZTEXT") or d.get("text") or d.get("body")
                                if not text and not d.get("ZMEDIAURL"):
                                    continue
                                raw_date = d.get("ZDATE") or d.get("ZTIMESTAMP") or d.get("date") or d.get("timestamp")
                                dt = self._convert_timestamp(raw_date)
                                sender = str(d.get("ZUSERID") or d.get("ZSENDER") or d.get("sender") or "Unknown")
                                sender_clean = viber_contacts.get(sender, sender)

                                self.viber_messages.append({
                                    "source": "Viber",
                                    "app": "Viber",
                                    "sender": sender_clean,
                                    "chat_name": str(d.get("ZCONVERSATION") or "Direct Chat"),
                                    "text": str(text or "[Viber Media/Photo]").strip(),
                                    "timestamp_utc": format_datetime_utc(dt) if dt else "N/A",
                                    "timestamp_local": format_datetime_local(dt) if dt else "N/A",
                                    "raw_datetime": dt
                                })
                            break
                        except Exception:
                            pass

                # Viber Call Logs
                for cl_tbl in ["ZPHONECALL", "ZPHONECALLRECORD", "calls"]:
                    if cl_tbl in tables:
                        try:
                            cur.execute(f"SELECT * FROM {cl_tbl}")
                            for r in cur.fetchall():
                                d = dict(r)
                                num = d.get("ZPHONENUMBER") or d.get("phone_number") or d.get("number") or "Unknown"
                                raw_date = d.get("ZDATE") or d.get("date") or 0
                                dur = d.get("ZDURATION") or d.get("duration") or 0
                                ctype = d.get("ZTYPE") or d.get("type") or "Viber VoIP Call"
                                dt = self._convert_timestamp(raw_date)
                                caller_name = viber_contacts.get(str(num), str(num))

                                self.viber_calls.append({
                                    "source": "Viber Call",
                                    "app": "Viber",
                                    "number": str(num),
                                    "contact_name": caller_name,
                                    "duration_seconds": int(dur),
                                    "call_type": str(ctype),
                                    "timestamp_utc": format_datetime_utc(dt) if dt else "N/A",
                                    "timestamp_local": format_datetime_local(dt) if dt else "N/A"
                                })
                            break
                        except Exception:
                            pass

                conn.close()
            except Exception:
                pass

    def _parse_signal(self):
        """
        Parses Signal Private Messenger database (signal.sqlite).
        """
        db_candidates = self.resolver.find_all_files(domain_contains="signal") + \
                        self.resolver.find_all_files(filename="signal.sqlite")

        seen_dbs = set()
        for db_p in db_candidates:
            if not db_p or db_p in seen_dbs or not os.path.exists(db_p):
                continue
            seen_dbs.add(db_p)

            try:
                conn = connect_readonly_sqlite(db_p)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = set(row[0] for row in cur.fetchall())

                # Parse Signal Contacts / Accounts
                for tbl in ["recipient", "SignalRecipient", "account", "TSContact"]:
                    if tbl in tables:
                        try:
                            cur.execute(f"SELECT * FROM {tbl}")
                            for row in cur.fetchall():
                                d = dict(row)
                                self.signal_records.append({
                                    "source": "Signal Metadata",
                                    "app": "Signal",
                                    "id": d.get("id") or d.get("uuid") or "N/A",
                                    "phone": d.get("phone") or d.get("e164") or "N/A",
                                    "name": d.get("profileName") or d.get("fullName") or "Signal Contact",
                                    "about": d.get("profileAbout") or ""
                                })
                            break
                        except Exception:
                            pass

                # Parse Signal Messages if present in unencrypted tables
                for tbl in ["TSInteraction", "messages", "model_TSMessage"]:
                    if tbl in tables:
                        try:
                            cur.execute(f"SELECT * FROM {tbl}")
                            for r in cur.fetchall():
                                d = dict(r)
                                text = d.get("body") or d.get("text")
                                if text:
                                    raw_date = d.get("date_sent") or d.get("date_received") or d.get("timestamp")
                                    dt = self._convert_timestamp(raw_date)
                                    self.all_messages.append({
                                        "source": "Signal",
                                        "app": "Signal",
                                        "sender": str(d.get("author_id") or "Signal User"),
                                        "chat_name": "Signal Chat",
                                        "text": str(text).strip(),
                                        "timestamp_utc": format_datetime_utc(dt) if dt else "N/A",
                                        "timestamp_local": format_datetime_local(dt) if dt else "N/A",
                                        "raw_datetime": dt
                                    })
                            break
                        except Exception:
                            pass
                conn.close()
            except Exception:
                pass

    def _parse_instagram(self):
        """
        Parses Instagram Direct Messages (direct_v2.sqlite, threads.db, messages.db).
        """
        db_candidates = self.resolver.find_all_files(domain_contains="instagram") + \
                        self.resolver.find_all_files(filename="direct_v2.sqlite")

        seen_dbs = set()
        for db_p in db_candidates:
            if not db_p or db_p in seen_dbs or not os.path.exists(db_p):
                continue
            seen_dbs.add(db_p)

            try:
                conn = connect_readonly_sqlite(db_p)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = set(row[0] for row in cur.fetchall())

                for m_tbl in ["messages", "direct_messages", "threads_messages"]:
                    if m_tbl in tables:
                        try:
                            cur.execute(f"SELECT * FROM {m_tbl} LIMIT 1000")
                            for r in cur.fetchall():
                                d = dict(r)
                                text = d.get("text") or d.get("message") or d.get("body")
                                if not text:
                                    continue
                                raw_date = d.get("timestamp") or d.get("date") or 0
                                dt = self._convert_timestamp(raw_date)
                                self.instagram_messages.append({
                                    "source": "Instagram Direct",
                                    "app": "Instagram",
                                    "sender": str(d.get("user_id") or d.get("sender_id") or "Instagram User"),
                                    "chat_name": str(d.get("thread_id") or "Direct Message"),
                                    "text": str(text).strip(),
                                    "timestamp_utc": format_datetime_utc(dt) if dt else "N/A",
                                    "timestamp_local": format_datetime_local(dt) if dt else "N/A",
                                    "raw_datetime": dt
                                })
                            break
                        except Exception:
                            pass
                conn.close()
            except Exception:
                pass

    def _parse_teams(self):
        """
        Parses Microsoft Teams chat databases (teams.db, SkypeTeams.sqlite).
        """
        db_candidates = self.resolver.find_all_files(domain_contains="skype.teams") + \
                        self.resolver.find_all_files(filename="teams.db")

        seen_dbs = set()
        for db_p in db_candidates:
            if not db_p or db_p in seen_dbs or not os.path.exists(db_p):
                continue
            seen_dbs.add(db_p)

            try:
                conn = connect_readonly_sqlite(db_p)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = set(row[0] for row in cur.fetchall())

                for tbl in ["chat_messages", "messages", "teams_chat"]:
                    if tbl in tables:
                        try:
                            cur.execute(f"SELECT * FROM {tbl} ORDER BY timestamp DESC LIMIT 500")
                            for r in cur.fetchall():
                                d = dict(r)
                                text = d.get("content") or d.get("body") or d.get("text")
                                if not text:
                                    continue
                                ts = d.get("timestamp") or d.get("created_time") or 0
                                dt = self._convert_timestamp(ts)
                                self.teams_messages.append({
                                    "source": "Microsoft Teams",
                                    "app": "Microsoft Teams",
                                    "sender": d.get("sender_name") or d.get("sender_id") or "Teams User",
                                    "chat_name": d.get("channel_name") or d.get("conversation_id") or "Direct Chat",
                                    "text": str(text).strip(),
                                    "timestamp_utc": format_datetime_utc(dt) if dt else "N/A",
                                    "timestamp_local": format_datetime_local(dt) if dt else "N/A",
                                    "raw_datetime": dt
                                })
                            break
                        except Exception:
                            pass
                conn.close()
            except Exception:
                pass

    def _parse_discord(self):
        """
        Parses Discord chat databases (discord.sqlite, chat.db).
        """
        db_candidates = self.resolver.find_all_files(domain_contains="discord") + \
                        self.resolver.find_all_files(filename="discord.sqlite")

        seen_dbs = set()
        for db_p in db_candidates:
            if not db_p or db_p in seen_dbs or not os.path.exists(db_p):
                continue
            seen_dbs.add(db_p)

            try:
                conn = connect_readonly_sqlite(db_p)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = set(row[0] for row in cur.fetchall())

                for tbl in ["messages", "channels_messages"]:
                    if tbl in tables:
                        try:
                            cur.execute(f"SELECT * FROM {tbl} LIMIT 500")
                            for r in cur.fetchall():
                                d = dict(r)
                                text = d.get("content") or d.get("body")
                                if text:
                                    dt = self._convert_timestamp(d.get("timestamp"))
                                    self.discord_messages.append({
                                        "source": "Discord",
                                        "app": "Discord",
                                        "sender": str(d.get("author_id") or "Discord User"),
                                        "chat_name": str(d.get("channel_id") or "Channel"),
                                        "text": str(text).strip(),
                                        "timestamp_utc": format_datetime_utc(dt) if dt else "N/A",
                                        "timestamp_local": format_datetime_local(dt) if dt else "N/A",
                                        "raw_datetime": dt
                                    })
                            break
                        except Exception:
                            pass
                conn.close()
            except Exception:
                pass

    def _parse_skype(self):
        """
        Parses Skype messaging databases (main.db, skype.db).
        """
        db_candidates = self.resolver.find_all_files(domain_contains="skype.skype") + \
                        self.resolver.find_all_files(filename="skype.db")

        seen_dbs = set()
        for db_p in db_candidates:
            if not db_p or db_p in seen_dbs or not os.path.exists(db_p):
                continue
            seen_dbs.add(db_p)

            try:
                conn = connect_readonly_sqlite(db_p)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = set(row[0] for row in cur.fetchall())

                for tbl in ["Messages", "messages"]:
                    if tbl in tables:
                        try:
                            cur.execute(f"SELECT * FROM {tbl} LIMIT 500")
                            for r in cur.fetchall():
                                d = dict(r)
                                text = d.get("body_xml") or d.get("body") or d.get("text")
                                if text:
                                    dt = self._convert_timestamp(d.get("timestamp"))
                                    self.skype_messages.append({
                                        "source": "Skype",
                                        "app": "Skype",
                                        "sender": str(d.get("author") or d.get("sender") or "Skype User"),
                                        "chat_name": str(d.get("convo_id") or "Conversation"),
                                        "text": str(text).strip(),
                                        "timestamp_utc": format_datetime_utc(dt) if dt else "N/A",
                                        "timestamp_local": format_datetime_local(dt) if dt else "N/A",
                                        "raw_datetime": dt
                                    })
                            break
                        except Exception:
                            pass
                conn.close()
            except Exception:
                pass

    def _parse_line(self):
        """
        Parses LINE messaging database (Line.sqlite).
        """
        db_candidates = self.resolver.find_all_files(domain_contains="naver.line") + \
                        self.resolver.find_all_files(filename="Line.sqlite")

        seen_dbs = set()
        for db_p in db_candidates:
            if not db_p or db_p in seen_dbs or not os.path.exists(db_p):
                continue
            seen_dbs.add(db_p)

            try:
                conn = connect_readonly_sqlite(db_p)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = set(row[0] for row in cur.fetchall())

                for tbl in ["ZMESSAGE", "messages"]:
                    if tbl in tables:
                        try:
                            cur.execute(f"SELECT * FROM {tbl} LIMIT 500")
                            for r in cur.fetchall():
                                d = dict(r)
                                text = d.get("ZTEXT") or d.get("text")
                                if text:
                                    dt = self._convert_timestamp(d.get("ZTIMESTAMP") or d.get("timestamp"))
                                    self.line_messages.append({
                                        "source": "Line",
                                        "app": "Line",
                                        "sender": str(d.get("ZSENDER") or "Line Contact"),
                                        "chat_name": "Line Chat",
                                        "text": str(text).strip(),
                                        "timestamp_utc": format_datetime_utc(dt) if dt else "N/A",
                                        "timestamp_local": format_datetime_local(dt) if dt else "N/A",
                                        "raw_datetime": dt
                                    })
                            break
                        except Exception:
                            pass
                conn.close()
            except Exception:
                pass

    def _parse_wechat(self):
        """
        Parses WeChat messaging database (MM.sqlite, message.db).
        """
        db_candidates = self.resolver.find_all_files(domain_contains="tencent.xin") + \
                        self.resolver.find_all_files(filename="MM.sqlite")

        seen_dbs = set()
        for db_p in db_candidates:
            if not db_p or db_p in seen_dbs or not os.path.exists(db_p):
                continue
            seen_dbs.add(db_p)

            try:
                conn = connect_readonly_sqlite(db_p)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = set(row[0] for row in cur.fetchall())

                for tbl in ["Chat_Message", "messages"]:
                    if tbl in tables:
                        try:
                            cur.execute(f"SELECT * FROM {tbl} LIMIT 500")
                            for r in cur.fetchall():
                                d = dict(r)
                                text = d.get("Message") or d.get("content") or d.get("text")
                                if text:
                                    dt = self._convert_timestamp(d.get("CreateTime") or d.get("timestamp"))
                                    self.wechat_messages.append({
                                        "source": "WeChat",
                                        "app": "WeChat",
                                        "sender": str(d.get("Des") or "WeChat Contact"),
                                        "chat_name": "WeChat Chat",
                                        "text": str(text).strip(),
                                        "timestamp_utc": format_datetime_utc(dt) if dt else "N/A",
                                        "timestamp_local": format_datetime_local(dt) if dt else "N/A",
                                        "raw_datetime": dt
                                    })
                            break
                        except Exception:
                            pass
                conn.close()
            except Exception:
                pass

    def _parse_protonmail(self):
        """
        Parses ProtonMail cached emails database (protonmail.db).
        """
        db_candidates = self.resolver.find_all_files(domain_contains="protonmail") + \
                        self.resolver.find_all_files(filename="protonmail.db")

        seen_dbs = set()
        for db_p in db_candidates:
            if not db_p or db_p in seen_dbs or not os.path.exists(db_p):
                continue
            seen_dbs.add(db_p)

            try:
                conn = connect_readonly_sqlite(db_p)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = set(row[0] for row in cur.fetchall())

                for tbl in ["messages", "cached_emails", "headers"]:
                    if tbl in tables:
                        try:
                            cur.execute(f"SELECT * FROM {tbl} LIMIT 200")
                            for r in cur.fetchall():
                                d = dict(r)
                                dt = self._convert_timestamp(d.get("time") or d.get("timestamp"))
                                self.protonmail_records.append({
                                    "source": "ProtonMail",
                                    "app": "ProtonMail",
                                    "sender": d.get("sender") or d.get("from") or "Proton User",
                                    "recipient": d.get("recipient") or d.get("to") or "N/A",
                                    "subject": d.get("subject") or d.get("title") or "[Encrypted Subject]",
                                    "timestamp_utc": format_datetime_utc(dt) if dt else "N/A",
                                    "timestamp_local": format_datetime_local(dt) if dt else "N/A"
                                })
                            break
                        except Exception:
                            pass
                conn.close()
            except Exception:
                pass

    def _parse_heuristic_third_party_apps(self):
        """
        Heuristic generic parser for ANY other unlisted app databases found in AppDomain-* or AppDomainGroup-*.
        """
        known_dbs = {
            "sms.db", "callhistory.storedata", "addressbook.sqlitedb", "notestore.sqlite",
            "safarihistory.db", "photos.sqlite", "datausage.sqlite", "chatstorage.sqlite",
            "contactsv2.sqlite", "truecaller.sqlite", "cloudrecordings.db", "recordings.sqlite",
            "voicemail.db", "tgdata.db", "signal.sqlite", "teams.db", "protonmail.db",
            "lightspeed.db", "viber.sqlite", "contacts.data", "direct_v2.sqlite"
        }

        # Find all SQLite databases from AppDomains
        for (dom, rel_p), real_p in self.resolver.file_map.items():
            if not ("AppDomain" in dom or "AppDomainGroup" in dom):
                continue
            base_fname = os.path.basename(rel_p).lower()
            if base_fname in known_dbs:
                continue
            if not any(base_fname.endswith(ext) for ext in [".sqlite", ".db", ".sqlitedb", ".storedata", ".data"]):
                continue

            # Check if file exists and inspect
            try:
                if not os.path.exists(real_p) or os.path.getsize(real_p) < 1024:
                    continue

                conn = connect_readonly_sqlite(real_p)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in cur.fetchall()]

                app_name = dom.replace("AppDomainGroup-group.", "").replace("AppDomain-", "").split(".")[-1].capitalize()

                for tbl in tables:
                    cur.execute(f"PRAGMA table_info({tbl})")
                    col_names = [c["name"].lower() for c in cur.fetchall()]

                    # Look for text column, timestamp column, sender column
                    text_col = next((c for c in col_names if c in ["text", "body", "message", "content", "msg", "ztext", "zbody"]), None)
                    time_col = next((c for c in col_names if c in ["timestamp", "date", "created_at", "time", "ztimestamp", "zdate", "timestamp_ms"]), None)
                    sender_col = next((c for c in col_names if c in ["sender", "from", "author", "user_id", "zsender", "zfrom", "sender_id"]), None)

                    if text_col and (time_col or sender_col):
                        try:
                            cur.execute(f"SELECT * FROM {tbl} WHERE {text_col} IS NOT NULL LIMIT 200")
                            for r in cur.fetchall():
                                d = dict(r)
                                text_val = str(d.get(text_col, "")).strip()
                                if not text_val or len(text_val) < 2:
                                    continue
                                dt = self._convert_timestamp(d.get(time_col)) if time_col else None
                                sender_val = str(d.get(sender_col, "App User")) if sender_col else "App User"

                                self.generic_third_party_messages.append({
                                    "source": f"Generic App ({app_name})",
                                    "app": app_name,
                                    "chat_name": f"{app_name} Chat ({tbl})",
                                    "sender": sender_val,
                                    "text": text_val,
                                    "timestamp_utc": format_datetime_utc(dt) if dt else "N/A",
                                    "timestamp_local": format_datetime_local(dt) if dt else "N/A",
                                    "raw_datetime": dt
                                })
                        except Exception:
                            pass
                conn.close()
            except Exception:
                pass
