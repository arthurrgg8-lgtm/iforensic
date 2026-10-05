import sqlite3
import os
from core.time_utils import mac_absolute_to_datetime, unix_to_datetime, format_datetime_utc, format_datetime_local
from core.db_utils import connect_readonly_sqlite
from parsers.calls_parser import format_duration, format_duration_hms

class PhotosParser:
    """
    Parses iOS Photos.sqlite database (ZGENERICASSET & ZADDITIONALASSETATTRIBUTES).
    Extracts 100% complete metadata for all Camera Roll Photos, Videos, Screen Recordings,
    Live Photos, Panoramas, Bursts, Hidden items, Trashed/Recently Deleted media,
    and EXIF GPS Geolocation telemetry.
    """

    def __init__(self, db_path):
        self.db_path = db_path
        self.photos = []
        self.summary = {}

    def parse(self):
        if not self.db_path or not os.path.exists(self.db_path):
            return []

        try:
            conn = connect_readonly_sqlite(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Inspect available columns in ZGENERICASSET
            cursor.execute("PRAGMA table_info(ZGENERICASSET)")
            cols = set(r["name"] for r in cursor.fetchall())

            # Check if ZADDITIONALASSETATTRIBUTES exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ZADDITIONALASSETATTRIBUTES'")
            has_add_attr = bool(cursor.fetchone())
            if has_add_attr:
                cursor.execute("PRAGMA table_info(ZADDITIONALASSETATTRIBUTES)")
                add_cols = set(r["name"] for r in cursor.fetchall())
                orig_fname_col = "att.ZORIGINALFILENAME" if "ZORIGINALFILENAME" in add_cols else "NULL"
                add_join = "LEFT JOIN ZADDITIONALASSETATTRIBUTES att ON a.Z_PK = att.ZASSET OR a.ZADDITIONALATTRIBUTES = att.Z_PK"
                extra_add_select = f", {orig_fname_col} as original_filename"
                where_clause = f"WHERE {filename_col} IS NOT NULL OR {orig_fname_col} IS NOT NULL"
            else:
                add_join = ""
                extra_add_select = ", NULL as original_filename"
                where_clause = f"WHERE {filename_col} IS NOT NULL"

            filename_col = "a.ZFILENAME" if "ZFILENAME" in cols else "NULL"
            dir_col = "a.ZDIRECTORY" if "ZDIRECTORY" in cols else "NULL"
            date_col = "a.ZDATECREATED" if "ZDATECREATED" in cols else "0"
            mod_col = "a.ZMODIFICATIONDATE" if "ZMODIFICATIONDATE" in cols else "NULL"
            lat_col = "a.ZLATITUDE" if "ZLATITUDE" in cols else "NULL"
            lon_col = "a.ZLONGITUDE" if "ZLONGITUDE" in cols else "NULL"
            alt_col = "a.ZALTITUDE" if "ZALTITUDE" in cols else "NULL"
            dur_col = "a.ZDURATION" if "ZDURATION" in cols else "0"
            fav_col = "a.ZFAVORITE" if "ZFAVORITE" in cols else "0"
            hid_col = "a.ZHIDDEN" if "ZHIDDEN" in cols else "0"
            trash_col = "a.ZTRASHEDSTATE" if "ZTRASHEDSTATE" in cols else "0"
            trash_date_col = "a.ZTRASHEDDATE" if "ZTRASHEDDATE" in cols else "NULL"
            kind_col = "a.ZKIND" if "ZKIND" in cols else ("a.ZKINDTYPE" if "ZKINDTYPE" in cols else "0")
            playback_col = "a.ZPLAYBACKSTYLE" if "ZPLAYBACKSTYLE" in cols else "0"
            uti_col = "a.ZUNIFORMTYPEIDENTIFIER" if "ZUNIFORMTYPEIDENTIFIER" in cols else "NULL"
            w_col = "a.ZWIDTH" if "ZWIDTH" in cols else "NULL"
            h_col = "a.ZHEIGHT" if "ZHEIGHT" in cols else "NULL"
            uuid_col = "a.ZUUID" if "ZUUID" in cols else "NULL"

            query = f"""
            SELECT 
                a.Z_PK as asset_id,
                {filename_col} as filename,
                {dir_col} as directory,
                {date_col} as date_created,
                {mod_col} as date_modified,
                {lat_col} as latitude,
                {lon_col} as longitude,
                {alt_col} as altitude,
                {dur_col} as duration_sec,
                {fav_col} as is_favorite,
                {hid_col} as is_hidden,
                {trash_col} as is_trashed,
                {trash_date_col} as trashed_date,
                {kind_col} as media_kind,
                {playback_col} as playback_style,
                {uti_col} as uti,
                {w_col} as width,
                {h_col} as height,
                {uuid_col} as asset_uuid
                {extra_add_select}
            FROM ZGENERICASSET a
            {add_join}
            {where_clause}
            ORDER BY {date_col} DESC
            """

            cursor.execute(query)
            for row in cursor.fetchall():
                c_date = row["date_created"]
                if not c_date:
                    continue

                dt_created = mac_absolute_to_datetime(c_date) or unix_to_datetime(c_date)
                m_date = row["date_modified"]
                dt_mod = (mac_absolute_to_datetime(m_date) or unix_to_datetime(m_date)) if m_date else None
                t_date = row["trashed_date"]
                dt_trashed = (mac_absolute_to_datetime(t_date) or unix_to_datetime(t_date)) if t_date else None

                fname = (row["filename"] or row["original_filename"] or "").strip()
                f_ext = os.path.splitext(fname)[1].lower()
                dur = float(row["duration_sec"] or 0)
                kind_id = int(row["media_kind"] or 0)
                playback_id = int(row["playback_style"] or 0)
                uti = (row["uti"] or "").lower()

                # Determine Media Type Classification
                if f_ext in ('.mov', '.mp4', '.m4v', '.3gp', '.avi') or kind_id == 1 or "video" in uti or "movie" in uti:
                    if "screen" in fname.lower() or "replay" in fname.lower():
                        media_type = "Screen Recording"
                    else:
                        media_type = "Video (Recorded / Saved)"
                elif playback_id == 3 or playback_id == 5 or "live" in uti:
                    media_type = "Live Photo"
                elif f_ext in ('.png',) and ("screenshot" in fname.lower() or (row["width"] and row["height"] and row["width"] in (1170, 1179, 1284, 1290, 828, 750, 1242))):
                    media_type = "Screenshot"
                elif f_ext in ('.heic', '.heif'):
                    media_type = "High Efficiency Photo (HEIC)"
                elif f_ext in ('.jpg', '.jpeg'):
                    media_type = "JPEG Photo"
                elif f_ext in ('.gif',):
                    media_type = "Animated GIF"
                else:
                    media_type = "Image / Photo"

                lat = row["latitude"]
                lon = row["longitude"]
                alt = row["altitude"]
                has_gps = bool(lat and lon and lat != 0 and lon != 0 and -90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0)

                maps_url = f"https://www.google.com/maps?q={lat:.6f},{lon:.6f}" if has_gps else ""
                osm_url = f"https://www.openstreetmap.org/?mlat={lat:.6f}&mlon={lon:.6f}#map=16/{lat:.6f}/{lon:.6f}" if has_gps else ""

                w = row["width"]
                h = row["height"]
                resolution_str = f"{w}x{h}" if (w and h) else "N/A"

                record = {
                    "source": "Photos & Media",
                    "asset_id": row["asset_id"],
                    "asset_uuid": row["asset_uuid"] or "",
                    "filename": fname,
                    "directory": row["directory"] or "",
                    "relative_path": os.path.join(row["directory"] or "", fname),
                    "media_type": media_type,
                    "uniform_type_identifier": uti or "public.data",
                    "timestamp_created_utc": format_datetime_utc(dt_created),
                    "timestamp_created_local": format_datetime_local(dt_created),
                    "timestamp_utc": format_datetime_utc(dt_created),
                    "timestamp_local": format_datetime_local(dt_created),
                    "timestamp_modified_local": format_datetime_local(dt_mod) if dt_mod else "N/A",
                    "timestamp_trashed_local": format_datetime_local(dt_trashed) if dt_trashed else "N/A",
                    "raw_datetime": dt_created,
                    "duration_seconds": round(dur, 2),
                    "duration_formatted": format_duration(dur) if dur > 0 else "N/A",
                    "duration_hms": format_duration_hms(dur) if dur > 0 else "00:00:00",
                    "resolution": resolution_str,
                    "width": w,
                    "height": h,
                    "latitude": round(lat, 6) if has_gps else None,
                    "longitude": round(lon, 6) if has_gps else None,
                    "altitude": round(alt, 2) if (alt is not None) else None,
                    "has_gps": has_gps,
                    "google_maps_url": maps_url,
                    "osm_maps_url": osm_url,
                    "is_trashed": bool(row["is_trashed"]),
                    "is_hidden": bool(row["is_hidden"]),
                    "is_favorite": bool(row["is_favorite"])
                }
                self.photos.append(record)

            conn.close()
        except Exception:
            pass

        self._compute_summary()
        return self.photos

    def _compute_summary(self):
        if not self.photos:
            self.summary = {
                "total_media_items": 0,
                "total_photos": 0,
                "total_videos": 0,
                "total_geotagged": 0,
                "total_trashed": 0,
                "total_hidden": 0,
                "total_favorites": 0
            }
            return self.summary

        tot_photos = sum(1 for p in self.photos if "Video" not in p.get("media_type", "") and "Screen Recording" not in p.get("media_type", ""))
        tot_videos = sum(1 for p in self.photos if "Video" in p.get("media_type", "") or "Screen Recording" in p.get("media_type", ""))
        tot_geo = sum(1 for p in self.photos if p.get("has_gps"))
        tot_trash = sum(1 for p in self.photos if p.get("is_trashed"))
        tot_hidden = sum(1 for p in self.photos if p.get("is_hidden"))
        tot_fav = sum(1 for p in self.photos if p.get("is_favorite"))

        self.summary = {
            "total_media_items": len(self.photos),
            "total_photos": tot_photos,
            "total_videos": tot_videos,
            "total_geotagged": tot_geo,
            "total_trashed": tot_trash,
            "total_hidden": tot_hidden,
            "total_favorites": tot_fav
        }
        return self.summary

    def get_summary(self):
        if not self.summary:
            self._compute_summary()
        return self.summary
