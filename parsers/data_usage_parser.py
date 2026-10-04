import sqlite3
import os
from core.db_utils import connect_readonly_sqlite

def format_bytes(bytes_val):
    if not bytes_val:
        return "0.00 MB"
    mb = bytes_val / (1024 * 1024)
    if mb >= 1024:
        return f"{mb / 1024:.2f} GB"
    return f"{mb:.2f} MB"

class DataUsageParser:
    """
    Parses iOS DataUsage.sqlite to extract cellular and Wi-Fi bandwidth consumption per App Bundle ID.
    """

    def __init__(self, db_path):
        self.db_path = db_path
        self.app_usage = []

    def parse(self):
        if not self.db_path or not os.path.exists(self.db_path):
            return []

        try:
            conn = connect_readonly_sqlite(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            query = """
            SELECT 
                p.zbundleid as bundle_id,
                SUM(u.zwifiin + u.zwifiout) as total_wifi_bytes,
                SUM(u.zwwanin + u.zwwanout) as total_cellular_bytes
            FROM zprocess p
            JOIN zliveusage u ON p.z_pk = u.zhasprocess
            GROUP BY p.zbundleid
            HAVING (total_wifi_bytes + total_cellular_bytes) > 0
            ORDER BY (total_wifi_bytes + total_cellular_bytes) DESC
            """
            cursor.execute(query)
            for row in cursor.fetchall():
                wifi_b = row["total_wifi_bytes"] or 0
                cell_b = row["total_cellular_bytes"] or 0
                tot_b = wifi_b + cell_b

                self.app_usage.append({
                    "bundle_id": row["bundle_id"],
                    "wifi_bytes": wifi_b,
                    "cellular_bytes": cell_b,
                    "total_bytes": tot_b,
                    "wifi_formatted": format_bytes(wifi_b),
                    "cellular_formatted": format_bytes(cell_b),
                    "total_formatted": format_bytes(tot_b)
                })

            conn.close()
        except Exception:
            pass

        return self.app_usage
