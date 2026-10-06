import os
import sqlite3
import re
from core.time_utils import unix_to_datetime, parse_any_time, format_datetime_local, format_datetime_utc
from core.db_utils import connect_readonly_sqlite

class UniversalAppEngine:
    """
    Universal Third-Party App & Messaging Carving Engine.
    Implements:
    1. Signature Registry for 15+ popular communication & social apps:
       (Telegram, Signal, WhatsApp, Viber, Discord, Messenger, Instagram, WeChat, Line, Slack, Skype, Snapchat, Session)
    2. Heuristic Generic Chat Carving: Automatically inspects ANY unlisted third-party SQLite database
       in the backup by detecting chat column fingerprints (text, sender, timestamp, chat_id).
    """

    APP_REGISTRY = {
        "Viber": {
            "domains": ["AppDomain-com.viber", "AppDomainGroup-group.com.viber"],
            "filenames": ["Viber.sqlite", "Contacts.data"],
            "table_signatures": ["messages", "conversations"],
            "query": "SELECT text, ztimestamp, zsender, zphonenumber FROM messages WHERE text IS NOT NULL ORDER BY ztimestamp DESC LIMIT 300",
            "mapping": {"text": "text", "time": "ztimestamp", "sender": "zsender"}
        },
        "Discord": {
            "domains": ["AppDomain-com.hammerandchisel.discord"],
            "filenames": ["discord.sqlite", "chat.db"],
            "table_signatures": ["messages", "channels"],
            "query": "SELECT content, timestamp, author_id, channel_id FROM messages WHERE content IS NOT NULL ORDER BY timestamp DESC LIMIT 300",
            "mapping": {"text": "content", "time": "timestamp", "sender": "author_id"}
        },
        "Facebook Messenger": {
            "domains": ["AppDomain-com.facebook.Messenger"],
            "filenames": ["lightspeed.sqlite", "threads_db2", "messages.db"],
            "table_signatures": ["messages", "threads"],
            "query": "SELECT text, timestamp_ms, sender_id FROM messages WHERE text IS NOT NULL ORDER BY timestamp_ms DESC LIMIT 300",
            "mapping": {"text": "text", "time": "timestamp_ms", "sender": "sender_id"}
        },
        "Instagram Direct": {
            "domains": ["AppDomain-com.burbn.instagram"],
            "filenames": ["direct.sqlite", "ig_direct.db"],
            "table_signatures": ["messages", "threads"],
            "query": "SELECT text, timestamp, user_id FROM messages WHERE text IS NOT NULL ORDER BY timestamp DESC LIMIT 300",
            "mapping": {"text": "text", "time": "timestamp", "sender": "user_id"}
        },
        "Slack": {
            "domains": ["AppDomain-com.tinyspeck.chatlyio"],
            "filenames": ["slack.sqlite", "teams.sqlite"],
            "table_signatures": ["messages", "channels"],
            "query": "SELECT text, ts, user, channel FROM messages WHERE text IS NOT NULL ORDER BY ts DESC LIMIT 300",
            "mapping": {"text": "text", "time": "ts", "sender": "user"}
        },
        "Skype": {
            "domains": ["AppDomain-com.skype.skype"],
            "filenames": ["main.db", "skype.db"],
            "table_signatures": ["Messages", "Conversations"],
            "query": "SELECT body_xml, timestamp, author FROM Messages WHERE body_xml IS NOT NULL ORDER BY timestamp DESC LIMIT 300",
            "mapping": {"text": "body_xml", "time": "timestamp", "sender": "author"}
        },
        "Line": {
            "domains": ["AppDomain-jp.naver.line"],
            "filenames": ["Line.sqlite", "chat.db"],
            "table_signatures": ["ZMESSAGE", "ZCHAT"],
            "query": "SELECT ZTEXT, ZTIMESTAMP, ZSENDER FROM ZMESSAGE WHERE ZTEXT IS NOT NULL ORDER BY ZTIMESTAMP DESC LIMIT 300",
            "mapping": {"text": "ZTEXT", "time": "ZTIMESTAMP", "sender": "ZSENDER"}
        },
        "WeChat": {
            "domains": ["AppDomain-com.tencent.xin"],
            "filenames": ["MM.sqlite", "message.db"],
            "table_signatures": ["Chat_Message", "Friend"],
            "query": "SELECT Message, CreateTime, Des FROM Chat_Message WHERE Message IS NOT NULL ORDER BY CreateTime DESC LIMIT 300",
            "mapping": {"text": "Message", "time": "CreateTime", "sender": "Des"}
        },
        "Session Private Messenger": {
            "domains": ["AppDomain-com.loki-project.loki-messenger"],
            "filenames": ["session.sqlite", "storage.sqlite"],
            "table_signatures": ["messages", "recipients"],
            "query": "SELECT body, timestamp, sender FROM messages WHERE body IS NOT NULL ORDER BY timestamp DESC LIMIT 300",
            "mapping": {"text": "body", "time": "timestamp", "sender": "sender"}
        },
        "Snapchat": {
            "domains": ["AppDomain-com.toyopagroup.picaboo", "AppDomainGroup-group.snapchat.picaboo"],
            "filenames": ["arroyo.db", "scdb.sqlite", "primary.docdb", "feed.db"],
            "table_signatures": ["conversation_message", "conversation", "feed_entries", "Friend"],
            "query": "SELECT message_content, creation_timestamp, sender_id FROM conversation_message WHERE message_content IS NOT NULL ORDER BY creation_timestamp DESC LIMIT 300",
            "mapping": {"text": "message_content", "time": "creation_timestamp", "sender": "sender_id"}
        }
    }

    def __init__(self, manifest_resolver=None):
        self.resolver = manifest_resolver
        self.discovered_app_messages = []
        self.app_statistics = {}

    def parse(self):
        return self.parse_all()

    def parse_all(self):
        """
        Executes signature-based extraction and heuristic generic discovery.
        """
        if not self.resolver:
            return {"messages": [], "app_counts": {}}

        # 1. Signature-based parsing
        self._parse_registered_apps()

        # 2. Heuristic discovery of unlisted third-party databases
        self._heuristic_scan_unlisted_databases()

        return {
            "messages": self.discovered_app_messages,
            "app_counts": self.app_statistics,
            "total_third_party_messages": len(self.discovered_app_messages)
        }

    def _parse_registered_apps(self):
        for app_name, conf in self.APP_REGISTRY.items():
            db_path = None
            # Lookup via resolver
            for fname in conf["filenames"]:
                db_path = self.resolver.find_file(filename=fname)
                if db_path and os.path.exists(db_path):
                    break

            if not db_path:
                for domain in conf["domains"]:
                    for fname in conf["filenames"]:
                        db_path = self.resolver.find_file(domain=domain, relative_path=f"Documents/{fname}", filename=fname)
                        if db_path and os.path.exists(db_path):
                            break
                    if db_path:
                        break

            if not db_path or not os.path.exists(db_path):
                continue

            try:
                conn = connect_readonly_sqlite(db_path)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()

                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tbls = set(row[0] for row in cur.fetchall())

                if any(st in tbls for st in conf["table_signatures"]):
                    try:
                        cur.execute(conf["query"])
                        m_map = conf["mapping"]
                        count = 0
                        for row in cur.fetchall():
                            d = dict(row)
                            raw_text = str(d.get(m_map["text"]) or "")
                            if not raw_text.strip():
                                continue

                            ts_val = d.get(m_map["time"])
                            dt_utc, dt_loc = parse_any_time(ts_val)
                            sender_val = str(d.get(m_map["sender"]) or "Unknown Sender")

                            self.discovered_app_messages.append({
                                "app": app_name,
                                "sender": sender_val,
                                "timestamp_utc": dt_utc,
                                "timestamp_local": dt_loc,
                                "text": raw_text[:300]
                            })
                            count += 1

                        if count > 0:
                            self.app_statistics[app_name] = count
                    except Exception:
                        pass

                conn.close()
            except Exception:
                pass

    def _heuristic_scan_unlisted_databases(self):
        """
        Scans all other SQLite databases in the backup looking for unrecognized messaging tables.
        """
        text_cols = {"text", "message", "body", "content", "msg", "ztext", "zbody", "payload"}
        time_cols = {"timestamp", "date", "created_at", "time", "ztimestamp", "zdate", "created_time"}
        sender_cols = {"sender", "sender_id", "from_id", "author", "user_id", "zsender", "from"}

        backup_dir = self.resolver.backup_dir
        for root, _, files in os.walk(backup_dir):
            for f in files:
                full_p = os.path.join(root, f)
                if not os.path.isfile(full_p) or os.path.getsize(full_p) < 4096:
                    continue

                try:
                    with open(full_p, "rb") as test_f:
                        hdr = test_f.read(16)
                        if not hdr.startswith(b"SQLite format 3\x00"):
                            continue

                    conn = connect_readonly_sqlite(full_p)
                    cur = conn.cursor()
                    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = [row[0] for row in cur.fetchall() if not row[0].startswith("sqlite_")]

                    for tbl in tables:
                        # Check table column names
                        cur.execute(f"PRAGMA table_info({tbl})")
                        cols = {row[1].lower(): row[1] for row in cur.fetchall()}

                        found_txt = list(text_cols.intersection(cols.keys()))
                        found_time = list(time_cols.intersection(cols.keys()))
                        found_sender = list(sender_cols.intersection(cols.keys()))

                        if found_txt and (found_time or found_sender):
                            col_t = cols[found_txt[0]]
                            col_tm = cols[found_time[0]] if found_time else None
                            col_s = cols[found_sender[0]] if found_sender else None

                            q = f"SELECT {col_t}"
                            if col_tm: q += f", {col_tm}"
                            if col_s: q += f", {col_s}"
                            q += f" FROM {tbl} WHERE {col_t} IS NOT NULL LIMIT 50"

                            cur.execute(q)
                            c_count = 0
                            for row in cur.fetchall():
                                txt = str(row[0] or "")
                                if len(txt) > 3 and not txt.startswith("{") and not txt.startswith("["):
                                    tm_v = row[1] if col_tm and len(row) > 1 else None
                                    s_v = row[2] if col_s and len(row) > 2 else "Unknown"
                                    dt_u, dt_l = parse_any_time(tm_v)

                                    self.discovered_app_messages.append({
                                        "app": f"Discovered Database ({f[:12]}/{tbl})",
                                        "sender": str(s_v or "App User"),
                                        "timestamp_utc": dt_u,
                                        "timestamp_local": dt_l,
                                        "text": txt[:300]
                                    })
                                    c_count += 1

                            if c_count > 0:
                                label = f"Auto-Carved ({tbl})"
                                self.app_statistics[label] = self.app_statistics.get(label, 0) + c_count

                    conn.close()
                except Exception:
                    pass

    @staticmethod
    def list_all_discovered_databases(backup_dir):
        """
        Catalogs all SQLite databases discovered in evidence for ad-hoc inspection.
        """
        discovered = []
        for root, _, files in os.walk(backup_dir):
            for f in files:
                full_p = os.path.join(root, f)
                if not os.path.isfile(full_p) or os.path.getsize(full_p) < 1024:
                    continue
                try:
                    with open(full_p, "rb") as test_f:
                        hdr = test_f.read(16)
                        if not hdr.startswith(b"SQLite format 3\x00"):
                            continue
                    conn = connect_readonly_sqlite(full_p)
                    cur = conn.cursor()
                    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = [row[0] for row in cur.fetchall() if not row[0].startswith("sqlite_")]
                    conn.close()

                    discovered.append({
                        "filename": f,
                        "path": full_p,
                        "relative_path": os.path.relpath(full_p, backup_dir),
                        "size_kb": round(os.path.getsize(full_p) / 1024, 2),
                        "table_count": len(tables),
                        "tables": tables
                    })
                except Exception:
                    pass
        return discovered

    @staticmethod
    def inspect_database_schema(db_path):
        """
        Inspects tables and columns of any arbitrary SQLite database file.
        """
        if not os.path.exists(db_path):
            return None

        schema = {}
        try:
            conn = connect_readonly_sqlite(db_path)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cur.fetchall()]

            for tbl in tables:
                cur.execute(f"PRAGMA table_info({tbl})")
                cols = [row[1] for row in cur.fetchall()]
                try:
                    cur.execute(f"SELECT COUNT(*) FROM {tbl}")
                    count = cur.fetchone()[0]
                except Exception:
                    count = 0
                schema[tbl] = {"columns": cols, "row_count": count}

            conn.close()
            return schema
        except Exception:
            return None
