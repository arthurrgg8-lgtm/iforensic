import sqlite3
import os
from core.time_utils import mac_absolute_to_datetime, unix_to_datetime, format_datetime_utc, format_datetime_local
from core.db_utils import connect_readonly_sqlite

class SafariParser:
    """
    Parses Safari History.db (history_items, history_visits).
    Extracts visited URLs, page titles, visit counts, search terms, and timestamps.
    """

    def __init__(self, db_path):
        self.db_path = db_path
        self.history = []

    def parse(self):
        if not self.db_path or not os.path.exists(self.db_path):
            return []

        try:
            conn = connect_readonly_sqlite(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            query = """
            SELECT 
                i.id as item_id,
                i.url,
                i.visit_count,
                v.visit_time,
                v.title
            FROM history_items i
            JOIN history_visits v ON i.id = v.history_item
            ORDER BY v.visit_time DESC
            """
            cursor.execute(query)
            for row in cursor.fetchall():
                dt = mac_absolute_to_datetime(row["visit_time"])
                if not dt:
                    dt = unix_to_datetime(row["visit_time"])

                record = {
                    "source": "Safari Web History",
                    "url": row["url"] or "",
                    "title": row["title"] or row["url"] or "Untitled Page",
                    "visit_count": row["visit_count"] or 1,
                    "timestamp_utc": format_datetime_utc(dt),
                    "timestamp_local": format_datetime_local(dt),
                    "raw_datetime": dt
                }
                self.history.append(record)

            conn.close()
        except Exception:
            pass

        return self.history
