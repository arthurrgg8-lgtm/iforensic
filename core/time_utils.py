import datetime
from datetime import timezone, timedelta

def mac_absolute_to_datetime(mac_time):
    """
    Converts Mac Absolute Time (seconds or nanoseconds since Jan 1, 2001) to datetime.
    """
    if mac_time is None or mac_time == 0:
        return None
    try:
        val = float(mac_time)
        # If timestamp is in nanoseconds (> 1e11), convert to seconds
        if val > 1e11:
            val = val / 1e9
        epoch_2001 = datetime.datetime(2001, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        return epoch_2001 + timedelta(seconds=val)
    except Exception:
        return None

def unix_to_datetime(unix_time):
    """
    Converts Unix timestamp (seconds or milliseconds) to datetime.
    """
    if unix_time is None or unix_time == 0:
        return None
    try:
        val = float(unix_time)
        if val > 1e11:  # Milliseconds
            val = val / 1000.0
        return datetime.datetime.fromtimestamp(val, tz=timezone.utc)
    except Exception:
        return None

def format_datetime_utc(dt):
    if not dt:
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")

def format_datetime_local(dt, offset_hours=5.75):
    """
    Default offset is +05:45 (Nepal Standard Time).
    """
    if not dt:
        return "N/A"
    local_tz = timezone(timedelta(hours=offset_hours))
    return dt.astimezone(local_tz).strftime("%Y-%m-%d %H:%M:%S %Z")

def apple_to_iso(mac_time, offset_hours=5.75):
    dt = mac_absolute_to_datetime(mac_time)
    if not dt:
        return "N/A", "N/A"
    return format_datetime_utc(dt), format_datetime_local(dt, offset_hours)

def parse_any_time(val, offset_hours=5.75):
    if not val:
        return "N/A", "N/A"
    try:
        f_val = float(val)
        if f_val < 1000000000: # Mac absolute epoch
            dt = mac_absolute_to_datetime(f_val)
        else: # Unix epoch
            dt = unix_to_datetime(f_val)
        return format_datetime_utc(dt), format_datetime_local(dt, offset_hours)
    except Exception:
        return "N/A", "N/A"
