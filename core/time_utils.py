import datetime
from datetime import timezone, timedelta

def to_datetime(val):
    """
    Enterprise universal datetime parser.
    Safely converts Mac Absolute Time (seconds, nanoseconds),
    Unix timestamp (seconds, milliseconds, microseconds, nanoseconds),
    ISO 8601 strings, and datetime objects into a timezone-aware UTC datetime.
    """
    if val is None or val == "" or val == "N/A" or val == 0 or val == "0":
        return None

    if isinstance(val, datetime.datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=timezone.utc)
        return val.astimezone(timezone.utc)

    if isinstance(val, str):
        val_str = val.strip()
        if "-" in val_str and (":" in val_str or "T" in val_str):
            try:
                dt = datetime.datetime.fromisoformat(val_str.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except Exception:
                pass

    try:
        f_val = float(val)
        if f_val == 0:
            return None

        # 1. Cocoa nanoseconds e.g. ~7.4e17 (iOS 16/17/18 sms.db)
        if f_val > 1e15:
            # Check Cocoa nanoseconds epoch (2001-01-01)
            cocoa_sec = f_val / 1e9
            epoch_2001 = datetime.datetime(2001, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
            test_dt = epoch_2001 + timedelta(seconds=cocoa_sec)
            if 2001 <= test_dt.year <= 2045:
                return test_dt

            # Otherwise Unix nanoseconds (1970-01-01)
            unix_sec = f_val / 1e9
            return datetime.datetime.fromtimestamp(unix_sec, tz=timezone.utc)

        # 2. Unix microseconds e.g. ~1.7e15
        if f_val > 1e13:
            return datetime.datetime.fromtimestamp(f_val / 1e6, tz=timezone.utc)

        # 3. Unix milliseconds e.g. ~1.7e12
        if f_val > 1e10:
            return datetime.datetime.fromtimestamp(f_val / 1e3, tz=timezone.utc)

        # 4. Unix seconds (> 1e9 e.g. 1.7e9 is year 2024+)
        if f_val > 1e9:
            return datetime.datetime.fromtimestamp(f_val, tz=timezone.utc)

        # 5. Mac Absolute seconds (< 1e9 e.g. 7.4e8 is year 2024)
        epoch_2001 = datetime.datetime(2001, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        test_cocoa = epoch_2001 + timedelta(seconds=f_val)
        if 2001 <= test_cocoa.year <= 2045:
            return test_cocoa

        # Fallback to Unix timestamp
        return datetime.datetime.fromtimestamp(f_val, tz=timezone.utc)
    except Exception:
        return None

def mac_absolute_to_datetime(mac_time):
    """
    Converts Mac Absolute Time (seconds or nanoseconds since Jan 1, 2001) to datetime.
    """
    if mac_time is None or mac_time == 0:
        return None
    try:
        val = float(mac_time)
        if val == 0:
            return None
        if val > 1e11:
            val = val / 1e9
        epoch_2001 = datetime.datetime(2001, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        res = epoch_2001 + timedelta(seconds=val)
        if res.year < 1990 or res.year > 2100:
            return None
        return res
    except Exception:
        return None

def unix_to_datetime(unix_time):
    """
    Converts Unix timestamp (seconds, milliseconds, microseconds, nanoseconds) to datetime.
    """
    if unix_time is None or unix_time == 0:
        return None
    try:
        val = float(unix_time)
        if val == 0:
            return None
        if val > 1e16:
            val = val / 1e9
        elif val > 1e13:
            val = val / 1e6
        elif val > 1e10:
            val = val / 1e3
        res = datetime.datetime.fromtimestamp(val, tz=timezone.utc)
        if res.year < 1970 or res.year > 2100:
            return None
        return res
    except Exception:
        return None

def format_datetime_utc(dt):
    if not dt:
        return "N/A"
    if isinstance(dt, (int, float, str)):
        dt = to_datetime(dt)
    if not dt or not isinstance(dt, datetime.datetime):
        return "N/A"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def format_datetime_local(dt, offset_hours=5.75):
    """
    Default offset is +05:45 (Nepal Standard Time).
    """
    if not dt:
        return "N/A"
    if isinstance(dt, (int, float, str)):
        dt = to_datetime(dt)
    if not dt or not isinstance(dt, datetime.datetime):
        return "N/A"
    local_tz = timezone(timedelta(hours=offset_hours))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(local_tz).strftime("%Y-%m-%d %H:%M:%S %Z")

def apple_to_iso(mac_time, offset_hours=5.75):
    dt = mac_absolute_to_datetime(mac_time)
    if not dt:
        return "N/A", "N/A"
    return format_datetime_utc(dt), format_datetime_local(dt, offset_hours)

def parse_any_time(val, offset_hours=5.75):
    dt = to_datetime(val)
    if not dt:
        return "N/A", "N/A"
    return format_datetime_utc(dt), format_datetime_local(dt, offset_hours)
