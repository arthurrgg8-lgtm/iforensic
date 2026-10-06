import sqlite3
import os
import plistlib
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

from core.time_utils import (
    mac_absolute_to_datetime,
    unix_to_datetime,
    format_datetime_utc,
    format_datetime_local,
    parse_any_time
)
from core.db_utils import connect_readonly_sqlite

def webkit_to_datetime(webkit_ts) -> Optional[datetime]:
    """
    Converts WebKit / Chromium timestamps (microseconds since 1601-01-01 UTC)
    or Unix timestamps into UTC datetime.
    """
    if not webkit_ts:
        return None
    try:
        ts = float(webkit_ts)
        if ts > 1000000000000000:  # WebKit microseconds
            unix_ts = (ts / 1_000_000) - 11644473600
            return datetime.fromtimestamp(unix_ts, timezone.utc)
        elif ts > 1000000000000:  # Unix milliseconds
            return datetime.fromtimestamp(ts / 1000, timezone.utc)
        elif ts < 1000000000:  # Mac Absolute (Apple)
            return datetime.fromtimestamp(ts + 978307200, timezone.utc)
        else:  # Standard Unix seconds
            return datetime.fromtimestamp(ts, timezone.utc)
    except Exception:
        return None

class UniversalBrowserParser:
    """
    Universal iOS Web Browsers and Downloads Forensic Parser.
    Extracts browsing history, visited URLs, page titles, search queries,
    and downloaded files/artifacts from:
    1. Apple Safari (History.db, Downloads.plist, Bookmarks.db)
    2. Google Chrome (com.google.chrome.ios - History, urls, visits, downloads)
    3. Mozilla Firefox (org.mozilla.ios.Firefox - browser.db, places.sqlite, downloads)
    4. DuckDuckGo Privacy Browser (com.duckduckgo.mobile.ios - Bookmarks, downloads)
    5. Brave Browser (com.brave.ios.browser - History, downloads)
    6. Microsoft Edge (com.microsoft.msedge - History, downloads)
    7. Opera (com.opera.OperaTouch - History, opera.db, downloads)
    8. Aloha Browser & Downloader (alohabrowser.alohabrowser - aloha.db, downloads)
    9. Heuristic discovery of ANY unlisted third-party browser databases
    10. Physical download carving across all browser containers
    """

    def __init__(self, db_path=None, manifest_resolver=None):
        self.db_path = db_path
        self.resolver = manifest_resolver
        self.history: List[Dict[str, Any]] = []
        self.downloads: List[Dict[str, Any]] = []
        self.bookmarks: List[Dict[str, Any]] = []
        self.seen_urls = set()

    def parse(self) -> List[Dict[str, Any]]:
        # 1. Parse explicit db_path if provided (legacy Safari compatibility)
        if self.db_path and os.path.exists(self.db_path):
            self._parse_safari_database(self.db_path)

        # 2. Multi-browser extraction if resolver is present
        if self.resolver:
            self._parse_safari()
            self._parse_chrome()
            self._parse_firefox()
            self._parse_duckduckgo()
            self._parse_brave()
            self._parse_edge()
            self._parse_opera()
            self._parse_aloha()
            self._parse_heuristic_browsers()
            self._carve_browser_downloads()

        # Sort all web visits chronologically
        self.history.sort(key=lambda x: x.get("timestamp_utc", ""), reverse=True)
        return self.history

    def get_downloads(self) -> List[Dict[str, Any]]:
        return self.downloads

    # -------------------------------------------------------------------------
    # 1. Safari Web History & Downloads
    # -------------------------------------------------------------------------

    def _parse_safari(self):
        db_candidates = (
            self.resolver.find_all_files(domain="HomeDomain", relative_path="Library/Safari/History.db") +
            self.resolver.find_all_files(filename="History.db") +
            self.resolver.find_all_files(filename="SafariHistory.db")
        )
        for db_p in db_candidates:
            if db_p and os.path.exists(db_p):
                self._parse_safari_database(db_p)
                break

        # Safari Downloads.plist
        dl_plist = self.resolver.find_file(filename="Downloads.plist") or \
                   self.resolver.find_file(domain="HomeDomain", relative_path="Library/Safari/Downloads.plist")
        if dl_plist and os.path.exists(dl_plist):
            try:
                with open(dl_plist, "rb") as f:
                    data = plistlib.load(f)
                    entries = data.get("DownloadHistory", data.get("Downloads", []))
                    if isinstance(entries, list):
                        for item in entries:
                            if isinstance(item, dict):
                                url = item.get("DownloadEntryURL", "")
                                path = item.get("DownloadEntryPath", "")
                                fname = os.path.basename(path) if path else "Downloaded_File"
                                total_b = item.get("DownloadEntryTotalBytes", 0)
                                date_v = item.get("DownloadEntryDate")
                                dt = parse_any_time(date_v)[0] if date_v else None

                                self.downloads.append({
                                    "browser": "Safari",
                                    "source": "Safari Downloads.plist",
                                    "url": url,
                                    "filename": fname,
                                    "file_path": path,
                                    "size_bytes": total_b,
                                    "size_kb": round(total_b / 1024, 2) if total_b else 0.0,
                                    "timestamp_utc": format_datetime_utc(dt) if dt else "N/A",
                                    "timestamp_local": format_datetime_local(dt) if dt else "N/A",
                                    "state": "Completed"
                                })
            except Exception:
                pass

    def _parse_safari_database(self, db_path: str):
        try:
            conn = connect_readonly_sqlite(db_path)
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
                url_str = row["url"] or ""
                v_time = row["visit_time"]
                dt = mac_absolute_to_datetime(v_time) or unix_to_datetime(v_time)
                key = ("Safari", url_str, str(v_time))
                if key in self.seen_urls:
                    continue
                self.seen_urls.add(key)

                self.history.append({
                    "browser": "Safari",
                    "source": "Safari Web History",
                    "url": url_str,
                    "title": row["title"] or url_str or "Untitled Page",
                    "visit_count": row["visit_count"] or 1,
                    "timestamp_utc": format_datetime_utc(dt),
                    "timestamp_local": format_datetime_local(dt),
                    "raw_datetime": dt
                })
            conn.close()
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # 2. Google Chrome (iOS)
    # -------------------------------------------------------------------------

    def _parse_chrome(self):
        chrome_dbs = (
            self.resolver.find_all_files(domain_contains="chrome") +
            self.resolver.find_all_files(filename="Chrome.sqlite") +
            self.resolver.find_all_files(filename="History")
        )
        seen = set()
        for db_p in chrome_dbs:
            if not db_p or db_p in seen or not os.path.exists(db_p):
                continue
            seen.add(db_p)

            try:
                conn = connect_readonly_sqlite(db_p)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = set(r[0] for r in cur.fetchall())

                # Chrome Visits & URLs
                if "urls" in tables:
                    join_visits = "JOIN visits v ON u.id = v.url" if "visits" in tables else ""
                    time_field = "v.visit_time" if "visits" in tables else "u.last_visit_time"
                    try:
                        cur.execute(f"""
                            SELECT u.url, u.title, u.visit_count, {time_field} as v_time
                            FROM urls u {join_visits}
                            ORDER BY {time_field} DESC LIMIT 2000
                        """)
                        for row in cur.fetchall():
                            url_str = str(row["url"] or "")
                            if not url_str:
                                continue
                            dt = webkit_to_datetime(row["v_time"])
                            key = ("Chrome", url_str, str(row["v_time"]))
                            if key in self.seen_urls:
                                continue
                            self.seen_urls.add(key)

                            self.history.append({
                                "browser": "Google Chrome",
                                "source": "Google Chrome iOS",
                                "url": url_str,
                                "title": str(row["title"] or url_str or "Chrome Page"),
                                "visit_count": row["visit_count"] or 1,
                                "timestamp_utc": format_datetime_utc(dt) if dt else "N/A",
                                "timestamp_local": format_datetime_local(dt) if dt else "N/A",
                                "raw_datetime": dt
                            })
                    except Exception:
                        pass

                # Chrome Downloads
                if "downloads" in tables:
                    try:
                        cur.execute("SELECT target_path, current_path, received_bytes, total_bytes, start_time, tab_url, mime_type FROM downloads")
                        for row in cur.fetchall():
                            t_path = row["target_path"] or row["current_path"] or ""
                            dt = webkit_to_datetime(row["start_time"])
                            self.downloads.append({
                                "browser": "Google Chrome",
                                "source": "Chrome Downloads DB",
                                "url": str(row["tab_url"] or ""),
                                "filename": os.path.basename(t_path) or "Chrome_Download",
                                "file_path": t_path,
                                "size_bytes": row["total_bytes"] or row["received_bytes"] or 0,
                                "size_kb": round((row["total_bytes"] or row["received_bytes"] or 0) / 1024, 2),
                                "timestamp_utc": format_datetime_utc(dt) if dt else "N/A",
                                "timestamp_local": format_datetime_local(dt) if dt else "N/A",
                                "state": "Completed" if row["received_bytes"] == row["total_bytes"] else "Interrupted",
                                "mime_type": str(row["mime_type"] or "")
                            })
                    except Exception:
                        pass

                conn.close()
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # 3. Mozilla Firefox (iOS)
    # -------------------------------------------------------------------------

    def _parse_firefox(self):
        ff_dbs = (
            self.resolver.find_all_files(domain_contains="firefox") +
            self.resolver.find_all_files(filename="browser.db") +
            self.resolver.find_all_files(filename="places.sqlite")
        )
        seen = set()
        for db_p in ff_dbs:
            if not db_p or db_p in seen or not os.path.exists(db_p):
                continue
            seen.add(db_p)

            try:
                conn = connect_readonly_sqlite(db_p)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = set(r[0] for r in cur.fetchall())

                for tbl in ["history", "moz_places", "visited"]:
                    if tbl in tables:
                        try:
                            cur.execute(f"SELECT * FROM {tbl} LIMIT 1000")
                            for row in cur.fetchall():
                                d = dict(row)
                                url_str = str(d.get("url") or "")
                                if not url_str or len(url_str) < 5:
                                    continue
                                raw_ts = d.get("created_at") or d.get("visit_date") or d.get("last_visit_time")
                                dt = webkit_to_datetime(raw_ts)
                                key = ("Firefox", url_str, str(raw_ts))
                                if key in self.seen_urls:
                                    continue
                                self.seen_urls.add(key)

                                self.history.append({
                                    "browser": "Mozilla Firefox",
                                    "source": "Firefox iOS",
                                    "url": url_str,
                                    "title": str(d.get("title") or url_str),
                                    "visit_count": d.get("visit_count", 1),
                                    "timestamp_utc": format_datetime_utc(dt) if dt else "N/A",
                                    "timestamp_local": format_datetime_local(dt) if dt else "N/A",
                                    "raw_datetime": dt
                                })
                        except Exception:
                            pass

                # Firefox Downloads
                if "downloads" in tables:
                    try:
                        cur.execute("SELECT * FROM downloads")
                        for r in cur.fetchall():
                            d = dict(r)
                            dt = webkit_to_datetime(d.get("created_at") or d.get("date"))
                            path_str = str(d.get("path") or d.get("filename") or "")
                            self.downloads.append({
                                "browser": "Mozilla Firefox",
                                "source": "Firefox Downloads DB",
                                "url": str(d.get("url") or ""),
                                "filename": os.path.basename(path_str) or "Firefox_Download",
                                "file_path": path_str,
                                "size_bytes": d.get("size", 0),
                                "size_kb": round(float(d.get("size", 0)) / 1024, 2),
                                "timestamp_utc": format_datetime_utc(dt) if dt else "N/A",
                                "timestamp_local": format_datetime_local(dt) if dt else "N/A",
                                "state": "Completed"
                            })
                    except Exception:
                        pass

                conn.close()
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # 4. DuckDuckGo Privacy Browser (iOS)
    # -------------------------------------------------------------------------

    def _parse_duckduckgo(self):
        ddg_dbs = (
            self.resolver.find_all_files(domain_contains="duckduckgo") +
            self.resolver.find_all_files(filename="Bookmarks.sqlite")
        )
        seen = set()
        for db_p in ddg_dbs:
            if not db_p or db_p in seen or not os.path.exists(db_p):
                continue
            seen.add(db_p)

            try:
                conn = connect_readonly_sqlite(db_p)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = set(r[0] for r in cur.fetchall())

                # Bookmarks and saved favorites
                for tbl in ["bookmarks", "Bookmark", "favorites", "tabs"]:
                    if tbl in tables:
                        try:
                            cur.execute(f"SELECT * FROM {tbl}")
                            for r in cur.fetchall():
                                d = dict(r)
                                url_str = str(d.get("url") or d.get("link") or "")
                                if url_str and url_str.startswith("http"):
                                    title = str(d.get("title") or d.get("name") or url_str)
                                    dt = webkit_to_datetime(d.get("created_at") or d.get("date"))
                                    self.history.append({
                                        "browser": "DuckDuckGo",
                                        "source": f"DuckDuckGo Saved ({tbl})",
                                        "url": url_str,
                                        "title": title,
                                        "visit_count": 1,
                                        "timestamp_utc": format_datetime_utc(dt) if dt else "N/A",
                                        "timestamp_local": format_datetime_local(dt) if dt else "N/A",
                                        "raw_datetime": dt
                                    })
                        except Exception:
                            pass
                conn.close()
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # 5. Brave Browser & Microsoft Edge
    # -------------------------------------------------------------------------

    def _parse_brave(self):
        self._parse_generic_chromium_browser("brave", "Brave Browser")

    def _parse_edge(self):
        self._parse_generic_chromium_browser("msedge", "Microsoft Edge")

    def _parse_opera(self):
        self._parse_generic_chromium_browser("opera", "Opera")

    def _parse_aloha(self):
        self._parse_generic_chromium_browser("aloha", "Aloha Browser")

    def _parse_generic_chromium_browser(self, domain_keyword: str, browser_label: str):
        dbs = self.resolver.find_all_files(domain_contains=domain_keyword)
        seen = set()
        for db_p in dbs:
            if not db_p or db_p in seen or not os.path.exists(db_p):
                continue
            if not any(db_p.endswith(ext) for ext in [".sqlite", ".db", "History"]):
                continue
            seen.add(db_p)

            try:
                conn = connect_readonly_sqlite(db_p)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = set(r[0] for r in cur.fetchall())

                if "urls" in tables or "history" in tables:
                    t_name = "urls" if "urls" in tables else "history"
                    try:
                        cur.execute(f"SELECT * FROM {t_name} LIMIT 500")
                        for r in cur.fetchall():
                            d = dict(r)
                            url_str = str(d.get("url") or "")
                            if not url_str or not url_str.startswith("http"):
                                continue
                            dt = webkit_to_datetime(d.get("last_visit_time") or d.get("visit_time") or d.get("timestamp"))
                            self.history.append({
                                "browser": browser_label,
                                "source": f"{browser_label} History",
                                "url": url_str,
                                "title": str(d.get("title") or url_str),
                                "visit_count": d.get("visit_count", 1),
                                "timestamp_utc": format_datetime_utc(dt) if dt else "N/A",
                                "timestamp_local": format_datetime_local(dt) if dt else "N/A",
                                "raw_datetime": dt
                            })
                    except Exception:
                        pass
                conn.close()
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # 6. Heuristic Scanner for ANY Other Discovered Browsers
    # -------------------------------------------------------------------------

    def _parse_heuristic_browsers(self):
        """
        Scans all AppDomain-* SQLite databases for unrecognized browser tables (urls, web_history).
        """
        known_browser_keywords = {"chrome", "firefox", "safari", "duckduckgo", "brave", "msedge", "opera", "aloha"}
        file_map = getattr(self.resolver, "file_map", {})

        for (domain, rel_p), real_p in file_map.items():
            if not ("AppDomain" in domain or "AppDomainGroup" in domain):
                continue
            dom_lower = domain.lower()
            if any(kw in dom_lower for kw in known_browser_keywords):
                continue
            if not any(rel_p.lower().endswith(ext) for ext in [".sqlite", ".db", ".sqlitedb"]):
                continue
            if not os.path.exists(real_p) or os.path.getsize(real_p) < 4096:
                continue

            try:
                conn = connect_readonly_sqlite(real_p)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [r[0] for r in cur.fetchall()]

                for tbl in tables:
                    cur.execute(f"PRAGMA table_info({tbl})")
                    cols = {c["name"].lower(): c["name"] for c in cur.fetchall()}
                    url_col = next((cols[c] for c in cols if c in ["url", "target_url", "visited_url", "web_url", "link"]), None)
                    title_col = next((cols[c] for c in cols if c in ["title", "page_title", "name"]), None)
                    time_col = next((cols[c] for c in cols if c in ["timestamp", "date", "created_at", "visit_time", "last_visit_time"]), None)

                    if url_col:
                        try:
                            cur.execute(f"SELECT * FROM {tbl} WHERE {url_col} LIKE 'http%' LIMIT 200")
                            app_name = domain.replace("AppDomain-", "").replace("AppDomainGroup-group.", "").split(".")[-1].capitalize()
                            for r in cur.fetchall():
                                d = dict(r)
                                u_val = str(d.get(url_col) or "")
                                t_val = str(d.get(title_col) or u_val) if title_col else u_val
                                dt = webkit_to_datetime(d.get(time_col)) if time_col else None
                                key = (app_name, u_val, str(dt))
                                if key in self.seen_urls:
                                    continue
                                self.seen_urls.add(key)

                                self.history.append({
                                    "browser": f"Third-Party ({app_name})",
                                    "source": f"Discovered Browser ({app_name})",
                                    "url": u_val,
                                    "title": t_val,
                                    "visit_count": 1,
                                    "timestamp_utc": format_datetime_utc(dt) if dt else "N/A",
                                    "timestamp_local": format_datetime_local(dt) if dt else "N/A",
                                    "raw_datetime": dt
                                })
                        except Exception:
                            pass
                conn.close()
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # 7. Physical Downloaded Files Carving Across All Containers
    # -------------------------------------------------------------------------

    def _carve_browser_downloads(self):
        """
        Locates physical downloaded files residing inside browser containers
        (Documents/Downloads, Documents/, or MediaDomain/Downloads).
        """
        file_map = getattr(self.resolver, "file_map", {})
        seen_paths = set(d.get("file_path") for d in self.downloads if d.get("file_path"))

        for (domain, rel_p), real_p in file_map.items():
            rel_lower = rel_p.lower()
            if not ("download" in rel_lower or "downloads" in rel_lower):
                continue
            if not os.path.exists(real_p) or os.path.isdir(real_p):
                continue
            if real_p in seen_paths:
                continue
            seen_paths.add(real_p)

            fname = os.path.basename(rel_p)
            ext = os.path.splitext(fname)[1].lower()
            if ext in [".sqlite", ".db", ".plist", ".dat", ".json", ".xml", ""]:
                continue

            try:
                sz = os.path.getsize(real_p)
            except Exception:
                sz = 0

            # Infer browser or origin from domain
            b_name = "Safari / iOS Files"
            dom_low = domain.lower()
            if "chrome" in dom_low: b_name = "Google Chrome"
            elif "firefox" in dom_low: b_name = "Mozilla Firefox"
            elif "duckduckgo" in dom_low: b_name = "DuckDuckGo"
            elif "brave" in dom_low: b_name = "Brave Browser"
            elif "msedge" in dom_low: b_name = "Microsoft Edge"
            elif "aloha" in dom_low: b_name = "Aloha Downloader"
            elif "opera" in dom_low: b_name = "Opera"

            self.downloads.append({
                "browser": b_name,
                "source": "Physical Container Download",
                "url": "N/A (Local Carved Download)",
                "filename": fname,
                "file_path": real_p,
                "relative_path": rel_p,
                "domain": domain,
                "size_bytes": sz,
                "size_kb": round(sz / 1024, 2),
                "timestamp_utc": "N/A",
                "timestamp_local": "N/A",
                "state": "Carved from Device Storage"
            })

# Backward compatibility alias
SafariParser = UniversalBrowserParser
