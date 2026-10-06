"""Read a labels CSV and turn its rows into marks that identify packets.

A mark is (epoch_microseconds, protocol, src_ip, dst_ip). Packets are identified by
absolute time rather than frame number, so the same marks work on a full capture and
on any file split from it.
"""
import calendar
import csv
import ipaddress
import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

try:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
except ImportError:  # pragma: no cover - Python < 3.9
    ZoneInfo = None
    ZoneInfoNotFoundError = Exception

TIME_COLS = ("timestamp", "time", "frame.time")
# Tried in order; a value is used only if it really is an IP address
# (some exports put a port number in the "dst_ip" column).
SRC_COLS = ("src_ip", "ip src", "ip.src", "source")
DST_COLS = ("ip dst", "dst_ip", "ip.dst", "destination")
PROTO_COLS = ("protocol",)

_TIME_RE = re.compile(r"(\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))?")
_ISO_DATE_RE = re.compile(r"(\d{4})-(\d{1,2})-(\d{1,2})")
_WS_DATE_RE = re.compile(r"([A-Za-z]{3})\s+(\d{1,2}),\s*(\d{4})")  # 'Jun 19, 2023'
_YEAR_RE = re.compile(r"(?<!\d)(20\d\d)(?!\d)")
_PATH_FULL_DATE_RE = re.compile(r"(?<!\d)(20\d\d)[-_.]?(\d\d)[-_.]?(\d\d)(?!\d)")
_PATH_MONTH_DAY_RE = re.compile(r"(?<!\d)(\d\d)[-_.](\d\d)(?!\d)")
_FIXED_OFFSET_RE = re.compile(r"^(?:UTC|GMT)?([+-])(\d{1,2})(?::?(\d{2}))?$", re.IGNORECASE)
_MONTHS = {m.lower(): i for i, m in enumerate(calendar.month_abbr) if m}


class CsvError(Exception):
    """A problem with the CSV that the user can fix."""


def time_of_day_us(text):
    """'Jun 19, 2023 12:15:58.387265000 ...' -> microseconds since midnight, or None."""
    m = _TIME_RE.search(text)
    if not m:
        return None
    h, mi, s, frac = m.groups()
    ns = int((frac or "").ljust(9, "0")[:9])
    return ((int(h) * 60 + int(mi)) * 60 + int(s)) * 10**6 + (ns + 500) // 1000


def date_from_text(text):
    """Find a full date in a timestamp string, or None."""
    m = _ISO_DATE_RE.search(text)
    if m:
        return date(int(m[1]), int(m[2]), int(m[3]))
    m = _WS_DATE_RE.search(text)
    if m and m[1].lower() in _MONTHS:
        return date(int(m[3]), _MONTHS[m[1].lower()], int(m[2]))
    return None


def guess_date_from_path(path, sample_timestamp=""):
    """Guess the capture date from the CSV's file or folder names.

    Understands '2023-06-19' / '20230619', and 'MM_DD' such as '06_19' when the year
    can be read from a timestamp in the file. Nearest name wins. Returns a date or None.
    """
    path = Path(path).resolve()
    year_match = _YEAR_RE.search(sample_timestamp)
    for part in [path.stem] + [p.name for p in path.parents]:
        m = _PATH_FULL_DATE_RE.search(part)
        try:
            if m:
                return date(int(m[1]), int(m[2]), int(m[3]))
            m = _PATH_MONTH_DAY_RE.search(part)
            if m and year_match:
                return date(int(year_match[1]), int(m[1]), int(m[2]))
        except ValueError:
            continue
    return None


def parse_timezone(name):
    """'Asia/Jerusalem', 'UTC', 'UTC+3' or '+03:00' -> tzinfo."""
    m = _FIXED_OFFSET_RE.match(name.strip())
    if m:
        sign = 1 if m[1] == "+" else -1
        return timezone(sign * timedelta(hours=int(m[2]), minutes=int(m[3] or 0)))
    if name.strip().upper() in ("UTC", "GMT", "Z"):
        return timezone.utc
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, TypeError):
        raise CsvError(
            f"Unknown time zone '{name}'. Use a name like 'Asia/Jerusalem' "
            "(on Windows this needs 'pip install tzdata') or a fixed offset like 'UTC+3'.")


def _first_ip(row, columns):
    for c in columns:
        v = (row.get(c) or "").strip()
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            pass
    return ""


def read_rows(csv_path):
    """Return (rows, columns) where columns maps lower-cased header -> real header."""
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        columns = {c.strip().lower(): c for c in (reader.fieldnames or []) if c and c.strip()}
        rows = list(reader)
    return rows, columns


def find_column(columns, candidates):
    return next((columns[c] for c in candidates if c in columns), None)


def first_timestamp(rows, columns):
    time_col = find_column(columns, TIME_COLS)
    return (rows[0].get(time_col) or "") if rows and time_col else ""


def has_dates(rows, columns):
    return date_from_text(first_timestamp(rows, columns)) is not None


def rows_to_marks(rows, columns, tz, default_date=None):
    """Convert CSV rows to a set of marks.

    Returns (marks, dates, skipped): marks is a set of
    (epoch_us, protocol, src_ip, dst_ip); dates is the set of capture dates seen;
    skipped counts rows whose time could not be read.
    """
    time_col = find_column(columns, TIME_COLS)
    if not time_col:
        raise CsvError(f"The CSV has no time column (expected one of: {', '.join(TIME_COLS)}).")
    proto_col = find_column(columns, PROTO_COLS)
    src_cols = [columns[c] for c in SRC_COLS if c in columns]
    dst_cols = [columns[c] for c in DST_COLS if c in columns]

    offsets = {}  # (date, hour) -> UTC offset in microseconds

    def utc_offset_us(day, tod_us):
        key = (day, tod_us // (3600 * 10**6))
        if key not in offsets:
            local = datetime(day.year, day.month, day.day, key[1] % 24, tzinfo=tz)
            offsets[key] = int(local.utcoffset().total_seconds()) * 10**6
        return offsets[key]

    marks, dates, skipped = set(), set(), 0
    for row in rows:
        text = row.get(time_col) or ""
        tod = time_of_day_us(text)
        if tod is None:
            skipped += 1
            continue
        day = date_from_text(text) or default_date
        if day is None:
            raise CsvError(f"The timestamp '{text.strip()}' has no date. Pass --date YYYY-MM-DD.")
        dates.add(day)
        epoch_us = calendar.timegm(day.timetuple()) * 10**6 + tod - utc_offset_us(day, tod)
        proto = (row.get(proto_col) or "").strip() if proto_col else ""
        marks.add((epoch_us, proto, _first_ip(row, src_cols), _first_ip(row, dst_cols)))
    return marks, dates, skipped
