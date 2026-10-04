import sqlite3
import os
from core.time_utils import mac_absolute_to_datetime, unix_to_datetime, format_datetime_utc, format_datetime_local
from core.db_utils import connect_readonly_sqlite

class PhotosParser:
    """
    Parses iOS Photos.sqlite (ZGENERICASSET).
    Extracts camera metadata, capture timestamps, and GPS latitude/longitude coordinates.
    """

    def __init__(self, db_path):
        self.db_path = db_path
        self.photos = []

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
                ZFILENAME,
                ZDIRECTORY,
                ZDATECREATED,
                ZLATITUDE,
                ZLONGITUDE,
                ZDURATION,
                ZFAVORITE,
                ZHIDDEN,
                ZTRASHEDSTATE
            FROM ZGENERICASSET
            WHERE ZFILENAME IS NOT NULL
            ORDER BY ZDATECREATED DESC
            """
            cursor.execute(query)
            for row in cursor.fetchall():
                dt = mac_absolute_to_datetime(row["ZDATECREATED"])
                if not dt:
                    dt = unix_to_datetime(row["ZDATECREATED"])

                lat = row["ZLATITUDE"]
                lon = row["ZLONGITUDE"]
                has_gps = bool(lat and lon and lat != 0 and lon != 0)

                record = {
                    "source": "Photos & Media",
                    "filename": row["ZFILENAME"],
                    "directory": row["ZDIRECTORY"] or "",
                    "timestamp_utc": format_datetime_utc(dt),
                    "timestamp_local": format_datetime_local(dt),
                    "raw_datetime": dt,
                    "latitude": lat if has_gps else None,
                    "longitude": lon if has_gps else None,
                    "has_gps": has_gps,
                    "is_trashed": bool(row["ZTRASHEDSTATE"]),
                    "is_favorite": bool(row["ZFAVORITE"])
                }
                self.photos.append(record)

            conn.close()
        except Exception:
            pass

        return self.photos
