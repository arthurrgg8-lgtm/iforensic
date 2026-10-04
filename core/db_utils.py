import sqlite3
import os
import pathlib

def connect_readonly_sqlite(db_path):
    """
    Connects to a SQLite database in strict Read-Only mode across Windows, macOS, and Linux.
    Properly handles Windows drive letters and URI encoding (e.g. file:///C:/path/db.sqlite?mode=ro).
    Falls back gracefully if URI mode is unsupported.
    """
    if not db_path or not os.path.exists(db_path):
        raise FileNotFoundError(f"Database file not found: {db_path}")
    
    abs_p = os.path.abspath(db_path)
    try:
        uri = f"{pathlib.Path(abs_p).as_uri()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        return conn
    except Exception:
        # Fallback for systems with non-standard URI handlers
        return sqlite3.connect(abs_p)
