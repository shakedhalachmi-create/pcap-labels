from datetime import date

import pytest

from pcap_labels import csv_reader as cr

HEADER = "timestamp,src_ip,tcp src_port,dst_ip,ip dst,tcp dst port,udp dst port,protocol,class,\n"


def write_csv(path, *lines):
    path.write_text(HEADER + "".join(l + "\n" for l in lines), encoding="utf-8")
    return path


def test_time_of_day():
    assert cr.time_of_day_us(" 2023 12:15:58.387265000 Jerusalem Daylight Time") == \
        ((12 * 60 + 15) * 60 + 58) * 10**6 + 387265
    assert cr.time_of_day_us("00:00:01") == 10**6
    assert cr.time_of_day_us("no time here") is None


def test_date_from_text():
    assert cr.date_from_text("Jun 19, 2023 12:15:58.387265000") == date(2023, 6, 19)
    assert cr.date_from_text("2023-06-19 12:15:58") == date(2023, 6, 19)
    assert cr.date_from_text(" 2023 12:15:58.387265000 Jerusalem Daylight Time") is None


def test_guess_date_from_path(tmp_path):
    ts = " 2023 12:15:58.387265000"
    assert cr.guess_date_from_path(tmp_path / "06_19" / "malicious.csv", ts) == date(2023, 6, 19)
    assert cr.guess_date_from_path(tmp_path / "labels_2023-06-19.csv") == date(2023, 6, 19)
    assert cr.guess_date_from_path(tmp_path / "20230619_labels.csv") == date(2023, 6, 19)
    # the file name wins over the folder name
    assert cr.guess_date_from_path(tmp_path / "06_20" / "06_19_labels.csv", ts) == date(2023, 6, 19)


def test_guess_date_needs_a_year(tmp_path):
    # month/day in the folder name but no year in the timestamp -> no guess from that folder
    guess = cr.guess_date_from_path(tmp_path / "06_19" / "malicious.csv", "12:15:58")
    assert guess is None or guess.year != 2023 or (guess.month, guess.day) != (6, 19)


def test_timezone_handles_summer_and_winter(tmp_path):
    tz = cr.parse_timezone("Asia/Jerusalem")
    rows, cols = cr.read_rows(write_csv(tmp_path / "a.csv", "12:00:00.000000,,,,,,,ARP,1,"))
    summer, _, _ = cr.rows_to_marks(rows, cols, tz, date(2023, 6, 19))   # UTC+3
    winter, _, _ = cr.rows_to_marks(rows, cols, tz, date(2023, 1, 19))   # UTC+2
    assert {m[0] for m in summer} == {1687165200 * 10**6}   # 2023-06-19 09:00:00 UTC
    assert {m[0] for m in winter} == {1674122400 * 10**6}   # 2023-01-19 10:00:00 UTC


def test_fixed_offset_timezone():
    assert cr.parse_timezone("UTC+3").utcoffset(None).total_seconds() == 3 * 3600
    assert cr.parse_timezone("-05:30").utcoffset(None).total_seconds() == -5.5 * 3600
    with pytest.raises(cr.CsvError):
        cr.parse_timezone("Not/AZone")


def test_rows_to_marks_uses_real_ip_columns(tmp_path):
    # "dst_ip" holds a port in this export; the address is in "ip dst"
    rows, cols = cr.read_rows(write_csv(
        tmp_path / "a.csv",
        " 2023 12:15:58.769286000 Jerusalem Daylight Time,192.0.2.10,,5353,224.0.0.251,,5353,MDNS,1,",
        " 2023 12:15:58.387265000 Jerusalem Daylight Time,,,,,,,ARP,1,",
        " 2023 12:15:58.387265000 Jerusalem Daylight Time,,,,,,,ARP,1,",   # duplicate row
        "garbage,,,,,,,ARP,1,"))
    marks, dates, skipped = cr.rows_to_marks(rows, cols, cr.parse_timezone("UTC+3"), date(2023, 6, 19))
    assert marks == {
        (1687166158769286, "MDNS", "192.0.2.10", "224.0.0.251"),
        (1687166158387265, "ARP", "", ""),
    }
    assert dates == {date(2023, 6, 19)}
    assert skipped == 1


def test_missing_date_is_an_error(tmp_path):
    rows, cols = cr.read_rows(write_csv(tmp_path / "a.csv", "12:00:00,,,,,,,ARP,1,"))
    with pytest.raises(cr.CsvError, match="--date"):
        cr.rows_to_marks(rows, cols, cr.parse_timezone("UTC"))


def test_date_inside_timestamp_needs_no_default(tmp_path):
    path = tmp_path / "a.csv"
    path.write_text('timestamp,protocol\n"Jun 19, 2023 12:00:00.000000000",ARP\n', encoding="utf-8")
    rows, cols = cr.read_rows(path)
    assert cr.has_dates(rows, cols)
    marks, dates, _ = cr.rows_to_marks(rows, cols, cr.parse_timezone("UTC"))
    assert dates == {date(2023, 6, 19)} and len(marks) == 1
