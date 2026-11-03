"""BRS (learn rating score) through the Pulse API of October 2026, against a stand-in for Pulse."""
import base64
import secrets
import struct
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from pymirea import Config, configure
from pymirea.circuit_breaker import CircuitBreaker
from pymirea.grades import MireaGrades, _LrsEntry

CUR, SEM, ATT = MireaGrades._CAT_CURRENT, MireaGrades._CAT_SEMESTER, MireaGrades._CAT_ATTENDANCE
ACH, ADD = MireaGrades._CAT_ACHIEVEMENTS, MireaGrades._CAT_ADDITIONAL
STUDENT = "00000002-0000-4000-8000-000000000002"
LOG = "00000001-0000-4000-8000-000000000001"
MATH, DRAWING = "00000006-0000-4000-8000-000000000006", "00000007-0000-4000-8000-000000000007"
MATH_T1, MATH_T3, DRAWING_T3 = "0000000b-0000-4000-8000-00000000000b", "0000000a-0000-4000-8000-00000000000a", "00000008-0000-4000-8000-000000000008"
YEAR_OLD, YEAR_NOW, AUTUMN = "00000005-0000-4000-8000-000000000005", "00000009-0000-4000-8000-000000000009", "00000003-0000-4000-8000-000000000003"


def _varint(n: int) -> bytes:
    out = bytearray()
    while n > 0x7F:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def s(field: int, value: str) -> bytes:
    data = value.encode()
    return bytes([(field << 3) | 2]) + _varint(len(data)) + data


def m(field: int, *parts: bytes) -> bytes:
    data = b"".join(parts)
    return bytes([(field << 3) | 2]) + _varint(len(data)) + data


def i(field: int, value: int) -> bytes:
    return bytes([field << 3]) + _varint(value)


def d(field: int, value: float) -> bytes:
    return bytes([(field << 3) | 1]) + struct.pack("<d", value)


def frame(payload: bytes) -> bytes:
    return struct.pack(">BI", 0, len(payload)) + payload + struct.pack(">BI", 0x80, 15) + b"grpc-status: 0"


def score_types(sem_max: int, att_max: int) -> bytes:
    return (
        m(2, i(1, 1), m(2, s(1, CUR), s(2, "Текущий контроль"), i(4, 40)),
             m(2, s(1, SEM), s(2, "Семестровый контроль"), i(4, sem_max)),
             m(2, s(1, ATT), s(2, "Посещения"), i(4, att_max)))
        + m(2, i(1, 2), m(2, s(1, ACH), s(2, "Достижения"), i(4, 10)), m(2, s(1, ADD), s(2, "Дополнительные"), i(4, 10)))
    )


TERM_PLANS = (
    m(1, i(1, 1), m(2, m(1, s(1, MATH), s(2, "Математический анализ")), m(2, s(1, MATH_T1))))
    + m(1, i(1, 3),
        m(2, m(1, s(1, DRAWING), s(2, "Начертательная геометрия")), m(2, s(1, DRAWING_T3))),
        m(2, m(1, s(1, MATH), s(2, "Математический анализ")), m(2, s(1, MATH_T3))))
    + m(1, i(1, 5), m(4, m(1, s(1, "00000004-0000-4000-8000-000000000004"), s(2, "Коллоидная химия"))))
)

LRS_REPORT = (
    m(1, s(1, MATH), s(2, "Математический анализ"),
      # first year: finished, every lesson accounted, scores final
      m(3, m(1, s(1, YEAR_OLD), s(2, AUTUMN)),
        m(2, m(2, i(1, 30), i(2, 19), i(3, 2), i(4, 32))),
        m(4, s(1, MATH_T1), score_types(30, 30),
          m(4, m(1, s(1, CUR), d(2, 21.0)), m(1, s(1, ATT), d(2, 19.0)), d(2, 40.0)), i(5, 120), d(7, 1.0))),
      # this year: 11 lessons ahead, only attendance so far
      m(3, m(1, s(1, YEAR_NOW), s(2, AUTUMN)),
        m(2, i(1, 11), m(2, i(1, 14), i(2, 1), i(4, 14))),
        m(4, s(1, MATH_T3), score_types(40, 20),
          m(4, m(1, s(1, ATT), d(2, 1.4)), d(2, 1.4)), i(5, 120), d(6, 15.71), d(7, 1.43))))
    + m(1, s(1, DRAWING), s(2, "Начертательная геометрия"),
        m(3, m(1, s(1, YEAR_NOW), s(2, AUTUMN)),
          m(2, i(1, 6), m(2, i(1, 7), i(4, 7))),
          m(4, s(1, DRAWING_T3), score_types(40, 20), i(5, 120), d(6, 17.14), d(7, 2.86))))
)

VISITING_LOGS = m(2, m(1, s(2, STUDENT)), m(2, s(1, LOG), s(2, "ТЕСТ-01-25")))


class BrsReportTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        configure(Config(session_keys=base64.b64encode(secrets.token_bytes(32)).decode()))
        self.requests = []  # (path, body)
        self.breaker = CircuitBreaker("test", failure_threshold=7, open_cooldown_s=20.0, half_open_max_calls=2)
        real_client = httpx.AsyncClient

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            self.requests.append((path, request.content[5:]))
            if path.endswith("/GetStudentTermPlansWithDisciplines"):
                return httpx.Response(200, content=frame(TERM_PLANS))
            if path.endswith("/GetAttendancesAndLRSByDisciplinesIds"):
                return httpx.Response(200, content=frame(LRS_REPORT))
            if path.endswith("/GetAvailableVisitingLogsOfStudent"):
                return httpx.Response(200, content=frame(VISITING_LOGS))
            return httpx.Response(599, text="unexpected request in a test: " + path)

        def client(**kwargs):
            kwargs.pop("transport", None)
            kwargs.pop("proxy", None)
            return real_client(transport=httpx.MockTransport(handler), **kwargs)

        for target, value in (
            ("pymirea.grades.make_async_client", client),
            ("pymirea.grades.get_breaker", lambda name: self.breaker),
            ("pymirea.grades.try_refresh_tokens", AsyncMock(return_value=False)),
        ):
            patcher = patch(target, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    async def grades(self, cookies):
        svc = MireaGrades(cookies)
        try:
            return await svc.get_grades()
        finally:
            await svc.close()

    def paths(self):
        return [p.rsplit("/", 1)[-1] for p, _ in self.requests]

    async def test_current_semester_scores_and_attendance_cap(self):
        cookies = {"Pulse.Auth.Cookie": "ok", "__brs_student_id": STUDENT, "__brs_visiting_log_id": LOG}
        result = await self.grades(cookies)
        self.assertTrue(result.success, result.message)
        self.assertEqual(self.paths(), ["GetStudentTermPlansWithDisciplines", "GetAttendancesAndLRSByDisciplinesIds"],
                         "no visiting-log round trip when the student is known, and never the retired report method")
        self.assertEqual([x.name for x in result.subjects], ["Математический анализ", "Начертательная геометрия"],
                         "only the semester in progress, not the finished first year")
        math, drawing = result.subjects
        self.assertEqual((math.discipline_id, math.attendance, math.current_control, math.total), (MATH, 1.4, 0.0, 1.4))
        self.assertAlmostEqual(math.attendance_max_possible, 17.11, "attendance now plus what the lessons ahead can give")
        self.assertEqual((math.semester_control_max, math.attendance_max, math.total_max), (40.0, 20.0, 120.0))
        self.assertEqual((drawing.total, drawing.attendance, drawing.attendance_max_possible), (0.0, 0.0, 17.14))
        self.assertEqual(result.semester, LOG)
        term_plan_body, report_body = self.requests[0][1], self.requests[1][1]
        self.assertEqual(term_plan_body, s(1, STUDENT))
        self.assertEqual(report_body, s(1, MATH) + s(1, DRAWING) + s(2, STUDENT), "every discipline of a real term, each once")

    async def test_student_is_looked_up_once_and_remembered(self):
        cookies = {"Pulse.Auth.Cookie": "ok"}
        result = await self.grades(cookies)
        self.assertTrue(result.success, result.message)
        self.assertEqual(self.paths()[0], "GetAvailableVisitingLogsOfStudent")
        self.assertEqual((cookies["__brs_student_id"], cookies["__brs_visiting_log_id"]), (STUDENT, LOG))
        self.assertEqual(result.semester, LOG)

    async def test_upstream_rejection_is_reported_not_hidden(self):
        cookies = {"Pulse.Auth.Cookie": "ok", "__brs_student_id": STUDENT, "__brs_visiting_log_id": LOG}
        with patch.object(MireaGrades, "TERM_PLANS_URL", "https://pulse.mirea.ru/gone"):
            result = await self.grades(cookies)
        self.assertFalse(result.success)
        self.assertEqual(result.message, "Ошибка сервера: 599")

    def test_without_a_term_plan_the_semester_with_lessons_ahead_wins(self):
        svc = object.__new__(MireaGrades)
        old = _LrsEntry(MATH, "Матан", YEAR_OLD, AUTUMN, "x", {CUR: 21.0}, {}, 40.0, 120, None, 0)
        now = _LrsEntry(MATH, "Матан", YEAR_NOW, AUTUMN, "y", {ATT: 1.4}, {}, 1.4, 120, 15.71, 11)
        entries, term = svc._current_semester_entries([old, now], {}, {})
        self.assertEqual((entries, term), ([now], None))
        entries, term = svc._current_semester_entries([old, now], {"x": 1, "y": 3}, {})
        self.assertEqual((entries, term), ([now], 3))


if __name__ == "__main__":
    unittest.main()
