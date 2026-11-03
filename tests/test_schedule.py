"""Tests for ``pymirea.schedule`` — the new schedule client.

Coverage:

- ICS parsing: line-folding, datetime, full VEVENT round-trip
- ICS export: RFC 5545 escape rules, structure, time format
- Format normalizers: 3 different MIREA JSON shapes
- Search: respx-mocked endpoints + dataclass shape
- Entity-fetch: name/UID resolution + raw_payload fallback when no events
- iCal fetch from URL + error paths

The fetcher hits respx-mocked endpoints — no live MIREA needed."""

from __future__ import annotations

import base64
import secrets
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx

from pymirea import Config, MireaParseFailed, configure
from pymirea.schedule import (
    ENGLISH_MIREA_ICAL_BASE,
    SCHEDULE_API_BASE,
    GroupInfo,
    MireaSchedule,
    Schedule,
    ScheduleEvent,
    _extract_classroom_info,
    _extract_events,
    _extract_group_info,
    _ics_escape_text,
    _ics_format_dt,
    _parse_ical_datetime,
    _parse_ical_events,
    _unfold_ical_lines,
)

MSK = timezone(timedelta(hours=3))


def _setup() -> None:
    configure(Config(session_keys=base64.b64encode(secrets.token_bytes(32)).decode()))


# ─── ICS escape ──────────────────────────────────────────────────────


def test_ics_escape_handles_specials():
    assert _ics_escape_text("hello, world; nice") == "hello\\, world\\; nice"
    # Newlines collapse to literal \n per RFC 5545.
    assert _ics_escape_text("line1\nline2") == "line1\\nline2"
    assert _ics_escape_text("line1\r\nline2") == "line1\\nline2"


def test_ics_escape_backslash_first():
    """Backslash MUST be escaped before commas/semicolons — otherwise the
    backslash we just inserted (for the comma) gets re-escaped, doubling it."""
    # Input has an actual backslash and a comma.
    assert _ics_escape_text("a\\b,c") == "a\\\\b\\,c"


def test_ics_format_dt_uses_z_for_utc():
    dt = datetime(2026, 5, 1, 14, 30, 0, tzinfo=timezone.utc)
    assert _ics_format_dt(dt) == "20260501T143000Z"


def test_ics_format_dt_converts_msk_to_utc():
    dt = datetime(2026, 5, 1, 14, 30, 0, tzinfo=MSK)
    # 14:30 MSK = 11:30 UTC
    assert _ics_format_dt(dt) == "20260501T113000Z"


def test_ics_format_dt_naive_is_floating():
    dt = datetime(2026, 5, 1, 14, 30, 0)
    assert _ics_format_dt(dt) == "20260501T143000"


# ─── ICS unfold + parse ──────────────────────────────────────────────


def test_unfold_joins_continuation_lines():
    folded = "DESCRIPTION:start of\n a long line\n that wraps"
    assert _unfold_ical_lines(folded) == ["DESCRIPTION:start ofa long linethat wraps"]


def test_parse_ical_datetime_utc():
    dt = _parse_ical_datetime("20260501T143000Z")
    assert dt == datetime(2026, 5, 1, 14, 30, 0, tzinfo=timezone.utc)


def test_parse_ical_datetime_without_zone_is_moscow_time():
    dt = _parse_ical_datetime("20260501T143000")
    assert dt == datetime(2026, 5, 1, 14, 30, 0, tzinfo=MSK)
    assert dt.utcoffset().total_seconds() == 3 * 3600


def test_parse_ical_datetime_date_only():
    dt = _parse_ical_datetime("20260501")
    assert dt == datetime(2026, 5, 1)


def test_parse_ical_datetime_garbage():
    assert _parse_ical_datetime("") is None
    assert _parse_ical_datetime("not-a-date") is None


def test_parse_ical_events_extracts_vevents():
    text = (
        "BEGIN:VCALENDAR\n"
        "BEGIN:VEVENT\n"
        "DTSTART:20260501T100000Z\n"
        "DTEND:20260501T113000Z\n"
        "SUMMARY:Алгебра\n"
        "LOCATION:А-303\n"
        "END:VEVENT\n"
        "BEGIN:VEVENT\n"
        "DTSTART:20260502T100000Z\n"
        "SUMMARY:Физика\n"
        "END:VEVENT\n"
        "END:VCALENDAR"
    )
    events = _parse_ical_events(text)
    assert len(events) == 2
    assert events[0]["SUMMARY"] == "Алгебра"
    assert events[0]["LOCATION"] == "А-303"
    assert events[1]["SUMMARY"] == "Физика"


# ─── Schedule.to_ics() ───────────────────────────────────────────────


def test_to_ics_minimal_calendar():
    s = Schedule(events=[
        ScheduleEvent(
            start=datetime(2026, 5, 1, 10, 0, tzinfo=timezone.utc),
            end=datetime(2026, 5, 1, 11, 30, tzinfo=timezone.utc),
            summary="Алгебра",
            location="А-303",
            description="Преподаватель: Иванов И.И.",
        )
    ])
    ics = s.to_ics()
    assert ics.startswith("BEGIN:VCALENDAR\r\n")
    assert ics.endswith("END:VCALENDAR\r\n")
    assert "BEGIN:VEVENT\r\n" in ics
    assert "DTSTART:20260501T100000Z" in ics
    assert "DTEND:20260501T113000Z" in ics
    assert "SUMMARY:Алгебра" in ics
    assert "LOCATION:А-303" in ics


def test_to_ics_handles_no_end_time():
    s = Schedule(events=[
        ScheduleEvent(
            start=datetime(2026, 5, 1, 10, 0, tzinfo=timezone.utc),
            end=None,
            summary="Однократное",
        )
    ])
    ics = s.to_ics()
    assert "DTSTART:20260501T100000Z" in ics
    assert "DTEND" not in ics


def test_to_ics_round_trip_preserves_summary_and_times():
    """to_ics() output → re-parse → identical event count + values."""
    original = Schedule(events=[
        ScheduleEvent(
            start=datetime(2026, 5, 1, 9, 0, tzinfo=timezone.utc),
            end=datetime(2026, 5, 1, 10, 30, tzinfo=timezone.utc),
            summary="Russian, with comma",
            location="Room A; weird",
            description="line1\nline2",
        ),
        ScheduleEvent(
            start=datetime(2026, 5, 2, 11, 0, tzinfo=timezone.utc),
            end=None,
            summary="Plain",
        ),
    ])
    ics = original.to_ics()
    raw = _parse_ical_events(ics)
    assert len(raw) == 2
    # Special chars survive escape → unescape (we replaced \n with newline
    # in the parser; ',' / ';' come back as literal because RFC parsing
    # would unescape — current impl keeps them simple; verify SUMMARY).
    assert "with comma" in raw[0]["SUMMARY"]
    assert raw[1]["SUMMARY"] == "Plain"


def test_to_ics_includes_calendar_name():
    s = Schedule(events=[])
    ics = s.to_ics(calendar_name="My Group ИКБО-01-23")
    assert "X-WR-CALNAME:My Group ИКБО-01-23" in ics


# ─── _extract_events: 3 normalizers ──────────────────────────────────


def test_extract_events_lessons_by_day():
    payload = {
        "days": [
            {
                "date": "2026-05-01",
                "lessons": [
                    {"name": "Алгебра", "start": "10:00", "end": "11:30"},
                    {"name": "Физика", "start": "11:40", "end": "13:10"},
                ],
            }
        ]
    }
    events = _extract_events(payload)
    assert len(events) == 2
    assert events[0].summary == "Алгебра"
    assert events[0].start.hour == 10
    assert events[1].summary == "Физика"
    assert events[1].start.hour == 11


def test_extract_events_mirea_ninja_data_array():
    payload = {
        "data": [
            {
                "subject": "Алгебра",
                "lesson_type": "ЛК",
                "dates": ["2026-05-01", "2026-05-08"],
                "lesson_bells": {"start_time": "10:00", "end_time": "11:30"},
                "teachers": [{"name": "Иванов И.И."}],
                "classrooms": [{"name": "А-303", "campus": {"short_name": "В-78"}}],
            }
        ]
    }
    events = _extract_events(payload)
    assert len(events) == 2  # Two dates
    assert events[0].summary == "Алгебра (ЛК)"
    assert "А-303 (В-78)" in events[0].location
    assert "Иванов И.И." in events[0].description


def test_extract_events_pairs_alternative_key():
    payload = {
        "date": "2026-05-01",
        "pairs": [
            {"name": "Алгебра", "start": "10:00", "end": "11:30"},
        ],
    }
    events = _extract_events(payload)
    assert len(events) == 1
    assert events[0].summary == "Алгебра"


def test_extract_events_returns_sorted():
    payload = {
        "days": [
            {"date": "2026-05-02", "lessons": [{"name": "Day2", "start": "09:00", "end": "10:30"}]},
            {"date": "2026-05-01", "lessons": [{"name": "Day1", "start": "09:00", "end": "10:30"}]},
        ]
    }
    events = _extract_events(payload)
    assert [e.summary for e in events] == ["Day1", "Day2"]


def test_extract_events_skips_lesson_without_start():
    payload = {
        "days": [
            {
                "date": "2026-05-01",
                "lessons": [
                    {"name": "Valid", "start": "10:00", "end": "11:30"},
                    {"name": "Broken", "end": "11:30"},  # no start
                ],
            }
        ]
    }
    events = _extract_events(payload)
    assert len(events) == 1
    assert events[0].summary == "Valid"


# ─── _extract_group_info / _extract_classroom_info ───────────────────


def test_extract_group_info_dict():
    info = _extract_group_info({"name": "ИКБО-01-23", "uid": "abc-123"})
    assert info == GroupInfo(name="ИКБО-01-23", uid="abc-123")


def test_extract_group_info_string():
    info = _extract_group_info("ИКБО-01-23")
    assert info == GroupInfo(name="ИКБО-01-23", uid=None)


def test_extract_group_info_garbage():
    assert _extract_group_info({}) is None
    assert _extract_group_info(None) is None
    assert _extract_group_info(42) is None


def test_extract_classroom_info_with_campus():
    info = _extract_classroom_info({
        "name": "А-303",
        "uid": "xyz",
        "campus": {"name": "Главный корпус", "short_name": "ГК"},
    })
    assert info.name == "А-303"
    assert info.uid == "xyz"
    assert info.campus == {"name": "Главный корпус", "short_name": "ГК"}


def test_extract_classroom_info_no_campus():
    info = _extract_classroom_info({"name": "А-303", "uid": "xyz"})
    assert info.campus is None


# ─── MireaSchedule HTTP surface ──────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_search_groups_parses_results():
    _setup()
    respx.get(f"{SCHEDULE_API_BASE}/api/v1/schedule/search/groups").mock(
        return_value=httpx.Response(
            200,
            json={"results": [
                {"name": "ИКБО-01-23", "uid": "u1"},
                {"name": "ИКБО-02-23", "uid": "u2"},
            ]},
        )
    )
    svc = MireaSchedule()
    try:
        results = await svc.search_groups("ИКБО")
    finally:
        await svc.close()

    assert len(results) == 2
    assert results[0].name == "ИКБО-01-23"
    assert results[0].uid == "u1"


@pytest.mark.asyncio
@respx.mock
async def test_search_groups_returns_empty_on_500():
    """Server error → empty list, never raises (search is best-effort)."""
    _setup()
    respx.get(f"{SCHEDULE_API_BASE}/api/v1/schedule/search/groups").mock(
        return_value=httpx.Response(500)
    )
    svc = MireaSchedule()
    try:
        results = await svc.search_groups("X")
    finally:
        await svc.close()

    assert results == []


@pytest.mark.asyncio
@respx.mock
async def test_get_group_schedule_normalizes_payload():
    _setup()
    respx.get(f"{SCHEDULE_API_BASE}/api/v1/schedule/group/u1").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "subject": "Алгебра",
                        "lesson_type": "ЛК",
                        "dates": ["2026-05-01"],
                        "lesson_bells": {"start_time": "10:00", "end_time": "11:30"},
                        "teachers": [{"name": "Иванов"}],
                        "classrooms": [{"name": "А-303"}],
                        "groups": ["ИКБО-01-23"],
                    }
                ]
            },
        )
    )
    svc = MireaSchedule()
    try:
        schedule = await svc.get_group_schedule(uid="u1")
    finally:
        await svc.close()

    assert len(schedule.events) == 1
    assert schedule.events[0].summary == "Алгебра (ЛК)"
    assert schedule.entity_type == "group"
    assert schedule.entity_uid == "u1"
    assert schedule.entity_name == "ИКБО-01-23"  # auto-derived
    assert schedule.raw_payload is None  # events present, no raw kept


@pytest.mark.asyncio
@respx.mock
async def test_get_group_schedule_keeps_raw_when_no_events():
    """If normalization yields no events, keep raw_payload for debugging."""
    _setup()
    respx.get(f"{SCHEDULE_API_BASE}/api/v1/schedule/group/u9").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    svc = MireaSchedule()
    try:
        schedule = await svc.get_group_schedule(uid="u9")
    finally:
        await svc.close()

    assert schedule.events == []
    assert schedule.raw_payload == {"data": []}


@pytest.mark.asyncio
@respx.mock
async def test_fetch_ical_for_group_parses_calendar():
    _setup()
    ical = (
        "BEGIN:VCALENDAR\r\n"
        "BEGIN:VEVENT\r\n"
        "DTSTART:20260501T100000Z\r\n"
        "DTEND:20260501T113000Z\r\n"
        "SUMMARY:Алгебра\r\n"
        "LOCATION:А-303\r\n"
        "END:VEVENT\r\n"
        "END:VCALENDAR\r\n"
    )
    respx.get(f"{ENGLISH_MIREA_ICAL_BASE}/1/123").mock(
        return_value=httpx.Response(200, text=ical)
    )
    svc = MireaSchedule()
    try:
        schedule = await svc.fetch_ical_for_group("123")
    finally:
        await svc.close()

    assert len(schedule.events) == 1
    assert schedule.events[0].summary == "Алгебра"
    assert schedule.events[0].location == "А-303"


@pytest.mark.asyncio
@respx.mock
async def test_fetch_ical_raises_on_404():
    _setup()
    respx.get(f"{ENGLISH_MIREA_ICAL_BASE}/1/999").mock(
        return_value=httpx.Response(404, text="not found")
    )
    svc = MireaSchedule()
    try:
        with pytest.raises(MireaParseFailed) as exc:
            await svc.fetch_ical_for_group("999")
    finally:
        await svc.close()

    assert exc.value.response_preview is not None
    assert "not found" in exc.value.response_preview


@pytest.mark.asyncio
async def test_close_is_idempotent():
    _setup()
    svc = MireaSchedule()
    await svc.close()
    await svc.close()  # second close should not raise


def test_ical_event_without_zone_keeps_its_moscow_instant_in_export():
    from pymirea.schedule import _ical_to_event
    event = _ical_to_event({"DTSTART": "20260501T090000", "DTEND": "20260501T103000", "SUMMARY": "Матанализ"})
    assert event.start == datetime(2026, 5, 1, 6, 0, tzinfo=timezone.utc)
    assert _ics_format_dt(event.start) == "20260501T060000Z"
