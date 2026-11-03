"""raise_for_error turns the library's failure messages into typed exceptions (opt-in)."""
import pytest

from pymirea import (
    MireaError,
    MireaParseFailed,
    MireaRateLimited,
    MireaServerError,
    MireaSessionExpired,
    error_from_message,
)
from pymirea.acs import AcsResult
from pymirea.grades import AttendanceDetailResult, GradesResult, ScheduleResult
from pymirea.session import AttendanceResult

# Every failure message the library produces today, with the class it must map to.
CASES = [
    ("Сессия МИРЭА истекла. Перелогиньтесь.", MireaSessionExpired),
    ("Сессия истекла. Перелогиньтесь в МИРЭА.", MireaSessionExpired),
    ("Сессия истекла.", MireaSessionExpired),
    ("Не удалось получить cookie авторизации Pulse. Перелогиньтесь.", MireaSessionExpired),
    ("БРС недоступен: не удалось получить cookie авторизации Pulse. Перелогиньтесь.", MireaSessionExpired),
    ("МИРЭА временно недоступна. Попробуйте через 18 сек.", MireaRateLimited),
    ("Ошибка сервера: 502", MireaServerError),
    ("HTTP 503", MireaServerError),
    ("Сервер не отвечает", MireaServerError),
    ("МИРЭА не отвечает. Попробуйте позже.", MireaServerError),
    ("Таймаут запроса к МИРЭА", MireaServerError),
    ("Ошибка сети: ConnectError", MireaServerError),
    ("МИРЭА временно недоступна. Попробуйте ещё раз.", MireaServerError),
    ("Пустой ответ gRPC", MireaParseFailed),
    ("Пустой ответ ACS", MireaParseFailed),
    ("Неизвестный ответ gRPC", MireaParseFailed),
    ("Не удалось распарсить ответ сервера", MireaParseFailed),
    ("Отметка пока недоступна", MireaError),
    ("Неверный QR-код. Ожидается код посещаемости МИРЭА.", MireaError),
    ("HTTP 403", MireaError),
]


@pytest.mark.parametrize("message,expected", CASES)
def test_library_messages_map_to_typed_errors(message, expected):
    error = error_from_message(message)
    assert type(error) is expected
    assert str(error) == message


def test_retry_after_and_status_code_are_kept():
    assert error_from_message("МИРЭА временно недоступна. Попробуйте через 18 сек.").retry_after == 18.0
    assert error_from_message("Ошибка сервера: 502").status_code == 502
    assert error_from_message("HTTP 429").retry_after is None
    assert isinstance(error_from_message("HTTP 429"), MireaRateLimited)


def test_dead_session_marker_wins_over_the_text():
    cookies = {"__pulse_bootstrap_failed_at": 1}
    assert isinstance(error_from_message("Пустой ответ gRPC", session_cookies=cookies), MireaSessionExpired)
    assert isinstance(error_from_message("Пустой ответ gRPC", session_cookies={}), MireaParseFailed)


@pytest.mark.parametrize("result_type", [AttendanceResult, GradesResult, ScheduleResult, AttendanceDetailResult])
def test_every_result_type_raises_on_failure_only(result_type):
    result_type(success=True, message="ok").raise_for_error()
    with pytest.raises(MireaSessionExpired):
        result_type(success=False, message="Сессия МИРЭА истекла. Перелогиньтесь.").raise_for_error()


def test_acs_result_raises_with_the_session_marker():
    AcsResult(success=True, message="ok", events=[]).raise_for_error()
    with pytest.raises(MireaSessionExpired):
        AcsResult(success=False, message="HTTP 401", events=[]).raise_for_error({"__pulse_bootstrap_failed_at": 1})


def test_all_typed_errors_share_the_base_class():
    for _, expected in CASES:
        assert issubclass(expected, MireaError)
