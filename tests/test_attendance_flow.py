"""Attendance marking end to end against a stand-in for Pulse. No request leaves the process."""
import base64
import secrets
import struct
import time
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from pymirea import Config, configure
from pymirea.circuit_breaker import CircuitBreaker
from pymirea.grades import MireaGrades
from pymirea.session import MireaAPI

QR = "https://attendance-app.mirea.ru/selfapprove?token=00000002-0000-4000-8000-000000000002"
EXPIRED = "Сессия МИРЭА истекла. Перелогиньтесь."


def _string(field_no: int, value: str) -> bytes:
    data = value.encode()
    return bytes([(field_no << 3) | 2, len(data)]) + data


def _frame(payload: bytes) -> bytes:
    return struct.pack(">BI", 0, len(payload)) + payload


# SelfApprove response: field 2 = approved { field 1 = lesson id }, as Pulse answers today.
APPROVED = _frame(bytes([(2 << 3) | 2, 38]) + _string(1, "00000001-0000-4000-8000-000000000001"))


class AttendanceFlowTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        configure(Config(session_keys=base64.b64encode(secrets.token_bytes(32)).decode()))
        self.answers = []      # scripted Pulse answers, one per self-approve request
        self.login_answers = []  # scripted answers to the Pulse login bootstrap, one per visit
        self.requests = []     # (host, path, Authorization) of every outgoing request
        self.cookie_headers = []  # (path, Cookie header) of every outgoing request
        self.breaker = CircuitBreaker("test", failure_threshold=7, open_cooldown_s=20.0, half_open_max_calls=2)
        real_client = httpx.AsyncClient

        def handler(request: httpx.Request) -> httpx.Response:
            self.requests.append((request.url.host, request.url.path, request.headers.get("Authorization")))
            self.cookie_headers.append((request.url.path, request.headers.get("Cookie", "")))
            if request.url == httpx.URL(MireaGrades.SELF_APPROVE_URL):
                answer = self.answers.pop(0)
                if isinstance(answer, Exception):
                    raise answer
                return answer
            if request.url.path == "/api/auth/login" and self.login_answers:
                return self.login_answers.pop(0)
            if request.url.host == "pulse.mirea.ru" and request.url.path == "/":
                return httpx.Response(200, text="<html>pulse web app</html>")
            if request.url.host == "sso.mirea.ru" and request.url.path == "/loop":
                return httpx.Response(302, headers={"Location": "https://sso.mirea.ru/loop"})
            if request.url.host == "sso.mirea.ru":
                return httpx.Response(200, text="<html>keycloak login form</html>")
            return httpx.Response(599, text="unexpected request in a test")

        def client(**kwargs):
            kwargs.pop("transport", None)
            kwargs.pop("proxy", None)
            return real_client(transport=httpx.MockTransport(handler), **kwargs)

        self.refresh = AsyncMock(side_effect=self.refreshed)
        self.refresh_works = True
        for target, value in (
            ("pymirea.grades.make_async_client", client),
            ("pymirea.grades.get_breaker", lambda name: self.breaker),
            ("pymirea.grades.try_refresh_tokens", self.refresh),
            ("pymirea.session.try_refresh_tokens", self.refresh),
        ):
            patcher = patch(target, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    async def refreshed(self, cookies):
        if not self.refresh_works or not cookies.get("refresh_token"):
            return False
        cookies.update(access_token="new-access", __token_refreshed_at=int(time.time() * 1000) + self.refresh.await_count)
        return True

    async def mark(self, **session):
        cookies = {"Pulse.Auth.Cookie": "stale", "access_token": "old-access", "refresh_token": "refresh", **session}
        return await self.mark_with(cookies), cookies

    async def mark_with(self, cookies):
        api = MireaAPI(session_cookies=cookies)
        try:
            return await api.mark_attendance(QR)
        finally:
            await api.close()

    def logins(self):
        return [r for r in self.requests if r[1] == "/api/auth/login"]

    @staticmethod
    def renewed_cookie():
        """Pulse's answer to /api/auth/login with a live Keycloak session: the new cookie and a redirect home."""
        return httpx.Response(302, headers={
            "Location": "https://pulse.mirea.ru/",
            "Set-Cookie": "Pulse.Auth.Cookie=fresh; Path=/; Secure; HttpOnly; SameSite=Lax",
        })

    @staticmethod
    def sso_login_page():
        """Pulse's answer when the Keycloak session is gone: off to the SSO login form."""
        return httpx.Response(302, headers={"Location": "https://sso.mirea.ru/realms/mirea/protocol/openid-connect/auth?client_id=attendance-app"})

    def approvals(self):
        return [r for r in self.requests if r[1].endswith("SelfApproveAttendanceThroughQRCode")]

    def assert_only_pulse(self):
        self.assertTrue(self.requests)
        self.assertEqual({host for host, _, _ in self.requests}, {"pulse.mirea.ru"}, "the retired attendance-app page is never requested")

    async def test_valid_session_is_marked_with_one_request(self):
        self.answers = [httpx.Response(200, content=APPROVED)]
        result, _ = await self.mark()
        self.assertEqual((result.success, result.message), (True, "Посещаемость отмечена"))
        self.assertEqual([auth for _, _, auth in self.approvals()], ["Bearer old-access"])
        self.refresh.assert_not_awaited()
        self.assert_only_pulse()

    async def test_expired_access_token_is_refreshed_and_the_mark_repeated(self):
        self.answers = [httpx.Response(401), httpx.Response(200, content=APPROVED)]
        result, cookies = await self.mark()
        self.assertEqual((result.success, result.message), (True, "Посещаемость отмечена"))
        self.assertEqual([auth for _, _, auth in self.approvals()], ["Bearer old-access", "Bearer new-access"])
        self.assertEqual(self.refresh.await_count, 1)
        self.assertEqual(cookies["access_token"], "new-access", "the caller gets the refreshed token to store")
        self.assert_only_pulse()

    async def test_session_without_refresh_token_asks_to_sign_in_again(self):
        self.answers = [httpx.Response(401)]
        result, _ = await self.mark(refresh_token="")
        self.assertEqual((result.success, result.message), (False, EXPIRED))
        self.assertEqual(len(self.approvals()), 1)
        self.assert_only_pulse()

    async def test_refused_refresh_asks_to_sign_in_again(self):
        self.refresh_works = False
        self.answers = [httpx.Response(401)]
        result, _ = await self.mark()
        self.assertEqual((result.success, result.message), (False, EXPIRED))
        self.assertEqual(len(self.approvals()), 1)

    async def test_still_unauthorized_after_refresh_stops_after_one_repeat(self):
        self.answers = [httpx.Response(401), httpx.Response(401)]
        result, _ = await self.mark()
        self.assertEqual((result.success, result.message), (False, EXPIRED))
        self.assertEqual(len(self.approvals()), 2, "one repeat, not a loop")
        self.assertEqual(self.refresh.await_count, 1)
        self.assertEqual(self.answers, [])

    async def test_rejected_cookie_is_renewed_through_sso_and_the_mark_repeated(self):
        self.answers = [httpx.Response(401), httpx.Response(200, content=APPROVED)]
        self.login_answers = [self.renewed_cookie()]
        result, cookies = await self.mark()
        self.assertEqual((result.success, result.message), (True, "Посещаемость отмечена"))
        self.assertEqual(len(self.approvals()), 2)
        self.assertEqual(len(self.logins()), 1)
        self.refresh.assert_not_awaited()
        self.assertEqual(cookies["Pulse.Auth.Cookie"], "fresh", "the caller gets the renewed cookie to store")
        self.assertNotIn("__pulse_bootstrap_failed_at", cookies)
        first, second = [c for path, c in self.cookie_headers if path.endswith("SelfApproveAttendanceThroughQRCode")]
        self.assertIn("Pulse.Auth.Cookie=stale", first)
        self.assertIn("Pulse.Auth.Cookie=fresh", second)
        self.assertNotIn("stale", second, "the rejected cookie is not sent next to the new one")
        self.assert_only_pulse()

    async def test_legacy_cookie_is_replaced_by_the_renamed_one(self):
        self.answers = [httpx.Response(401), httpx.Response(200, content=APPROVED)]
        self.login_answers = [self.renewed_cookie()]
        cookies = {".AspNetCore.Cookies": "old", "access_token": "old-access", "refresh_token": "refresh"}
        result = await self.mark_with(cookies)
        self.assertEqual((result.success, result.message), (True, "Посещаемость отмечена"))
        self.assertEqual(cookies["Pulse.Auth.Cookie"], "fresh")
        self.assertNotIn(".AspNetCore.Cookies", cookies)
        second = [c for path, c in self.cookie_headers if path.endswith("SelfApproveAttendanceThroughQRCode")][1]
        self.assertNotIn(".AspNetCore.Cookies", second)

    async def test_dead_sso_session_is_remembered_and_not_replayed(self):
        self.refresh_works = False
        self.answers = [httpx.Response(401), httpx.Response(401)]
        self.login_answers = [self.sso_login_page()]
        cookies = {"Pulse.Auth.Cookie": "stale", "access_token": "old-access", "refresh_token": "refresh"}
        result = await self.mark_with(cookies)
        self.assertEqual((result.success, result.message), (False, EXPIRED))
        self.assertEqual(len(self.logins()), 1)
        self.assertIn("__pulse_bootstrap_failed_at", cookies)
        result = await self.mark_with(cookies)
        self.assertEqual((result.success, result.message), (False, EXPIRED))
        self.assertEqual(len(self.logins()), 1, "no SSO round trip within the back-off window")
        self.assertEqual(self.answers, [])

    async def test_sso_redirect_loop_is_an_expired_session_not_an_outage(self):
        self.refresh_works = False
        self.answers = [httpx.Response(401), httpx.Response(401)]
        self.login_answers = [httpx.Response(302, headers={"Location": "https://sso.mirea.ru/loop"})]
        cookies = {"Pulse.Auth.Cookie": "stale", "access_token": "old-access", "refresh_token": "refresh"}
        result = await self.mark_with(cookies)
        self.assertEqual((result.success, result.message), (False, EXPIRED))
        self.assertIn("__pulse_bootstrap_failed_at", cookies)
        self.assertEqual(self.breaker._state, "closed", "a looping SSO is not counted as a Pulse outage")
        result = await self.mark_with(cookies)
        self.assertEqual((result.success, result.message), (False, EXPIRED))
        self.assertEqual(len(self.logins()), 1, "the loop is not replayed within the back-off window")

    async def test_stale_keycloak_flow_cookies_are_not_replayed_to_sso(self):
        self.refresh_works = False
        self.answers = [httpx.Response(401)]
        self.login_answers = [self.sso_login_page()]
        cookies = {"Pulse.Auth.Cookie": "stale", "KEYCLOAK_IDENTITY": "id", "KEYCLOAK_SESSION": "sess",
                   "AUTH_SESSION_ID": "old-flow", "KC_RESTART": "old-restart", "KC_AUTH_SESSION_HASH": "h"}
        await self.mark_with(cookies)
        sso = [c for path, c in self.cookie_headers if path.startswith("/realms/")]
        self.assertEqual(len(sso), 1)
        self.assertIn("KEYCLOAK_IDENTITY=id", sso[0])
        self.assertIn("KEYCLOAK_SESSION=sess", sso[0])
        for stale in ("AUTH_SESSION_ID", "KC_RESTART", "KC_AUTH_SESSION_HASH"):
            self.assertNotIn(stale, sso[0])

    async def test_upstream_error_is_reported_as_such(self):
        self.answers = [httpx.Response(502)]
        result, _ = await self.mark()
        self.assertEqual((result.success, result.message), (False, "Ошибка сервера: 502"))
        self.assertEqual(len(self.approvals()), 1)
        self.refresh.assert_not_awaited()
        self.assert_only_pulse()

    async def test_network_failure_is_reported_as_such(self):
        self.answers = [httpx.ConnectTimeout("timed out")]
        result, _ = await self.mark()
        self.assertEqual((result.success, result.message), (False, "Сервер не отвечает"))

    async def test_open_circuit_breaker_tells_when_to_retry(self):
        for _ in range(7):
            await self.breaker.record_failure()
        result, _ = await self.mark()
        self.assertFalse(result.success)
        self.assertRegex(result.message, r"^МИРЭА временно недоступна\. Попробуйте через \d+ сек\.$")
        self.assertEqual(self.requests, [], "nothing is sent while the breaker is open")

    async def test_no_outcome_is_reported_as_unknown_response(self):
        for answers in ([httpx.Response(401)], [httpx.Response(502)], [httpx.Response(403)], [httpx.Response(200, content=b"")]):
            self.answers = list(answers)
            self.refresh_works = False
            result, _ = await self.mark()
            self.assertFalse(result.success)
            self.assertNotIn("Неизвестный ответ", result.message)
            self.assertNotIn("Проверьте вручную", result.message)
            self.assertTrue(result.message)


if __name__ == "__main__":
    unittest.main()
