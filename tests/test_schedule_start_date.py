"""MireaGrades.get_schedule asks Pulse for the requested days, from start_date when given."""
import base64
import secrets
from datetime import date, datetime
from unittest.mock import AsyncMock
from zoneinfo import ZoneInfo

import pytest

from pymirea import Config, configure
from pymirea.grades import MireaGrades


@pytest.fixture
def grades():
    configure(Config(session_keys=base64.b64encode(secrets.token_bytes(32)).decode()))
    svc = object.__new__(MireaGrades)
    svc._ensure_pulse_cookie = AsyncMock(return_value=(True, None))
    svc._grpc_unary = AsyncMock(return_value=(b"", None))
    svc._encode_date_request = lambda y, m, d: f"{y:04d}-{m:02d}-{d:02d}".encode()
    return svc


def requested_days(svc):
    return sorted(call.args[1].decode() for call in svc._grpc_unary.await_args_list)


@pytest.mark.asyncio
async def test_start_date_selects_the_days(grades):
    result = await grades.get_schedule(days=3, start_date=date(2026, 12, 30))
    assert result.success
    assert requested_days(grades) == ["2026-12-30", "2026-12-31", "2027-01-01"]


@pytest.mark.asyncio
async def test_default_starts_today_in_moscow(grades):
    result = await grades.get_schedule(days=1)
    assert result.success
    assert requested_days(grades) == [datetime.now(ZoneInfo("Europe/Moscow")).date().isoformat()]


@pytest.mark.asyncio
async def test_days_stays_positional_for_existing_callers(grades):
    await grades.get_schedule(2)
    assert len(requested_days(grades)) == 2
