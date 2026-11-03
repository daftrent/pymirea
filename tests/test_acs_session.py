"""ACS renews the Pulse session like BRS and attendance do. In-process stand-in for Pulse."""
import base64
import secrets
import struct
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from pymirea import Config, configure
from pymirea.acs import _GET_ME_URL, MireaACS
from pymirea.circuit_breaker import CircuitBreaker

EXPIRED = "Сессия МИРЭА истекла. Перелогиньтесь."
ME = struct.pack(">BI", 0, 2) + b"\x08\x01" + struct.pack(">BI", 0x80, 15) + b"grpc-status: 0"


class AcsSessionRenewalTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        configure(Config(session_keys=base64.b64encode(secrets.token_bytes(32)).decode()))
        self.login_answers = []
        self.requests = []  # (host, path, Cookie header)
        self.breaker = CircuitBreaker("test", failure_threshold=7, open_cooldown_s=20.0, half_open_max_calls=2)
        real_client = httpx.AsyncClient

        def handler(request: httpx.Request) -> httpx.Response:
            cookie = request.headers.get("Cookie", "")
            self.requests.append((request.url.host, request.url.path, cookie))
            if request.url.path.endswith("/GetMeInfo"):
                return httpx.Response(200, content=ME) if "Pulse.Auth.Cookie=fresh" in cookie else httpx.Response(401)
            if request.url.path == "/api/auth/login" and self.login_answers:
                return self.login_answers.pop(0)
            if request.url.host == "pulse.mirea.ru" and request.url.path == "/":
                return httpx.Response(200, text="<html>pulse web app</html>")
            if request.url.host == "sso.mirea.ru":
                return httpx.Response(200, text="<html>keycloak login form</html>")
            return httpx.Response(599, text="unexpected request in a test")

        def client(**kwargs):
            kwargs.pop("transport", None)
            kwargs.pop("proxy", None)
            return real_client(transport=httpx.MockTransport(handler), **kwargs)

        self.refresh = AsyncMock(return_value=False)
        for target, value in (
            ("pymirea.acs.make_async_client", client),
            ("pymirea.grades.make_async_client", client),
            ("pymirea.acs.get_breaker", lambda name: self.breaker),
            ("pymirea.grades.get_breaker", lambda name: self.breaker),
            ("pymirea.grades.try_refresh_tokens", self.refresh),
        ):
            patcher = patch(target, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    async def call(self, cookies):
        acs = MireaACS(cookies)
        try:
            return await acs._grpc_unary(_GET_ME_URL, b"")
        finally:
            await acs.close()

    def me_calls(self):
        return [c for host, path, c in self.requests if path.endswith("/GetMeInfo")]

    @staticmethod
    def renewed_cookie():
        return httpx.Response(302, headers={
            "Location": "https://pulse.mirea.ru/",
            "Set-Cookie": "Pulse.Auth.Cookie=fresh; Path=/; Secure; HttpOnly; SameSite=Lax",
        })

    async def test_rejected_cookie_is_renewed_and_the_call_repeated(self):
        self.login_answers = [self.renewed_cookie()]
        cookies = {"Pulse.Auth.Cookie": "stale", "KEYCLOAK_IDENTITY": "id"}
        payload, err = await self.call(cookies)
        self.assertIsNone(err)
        self.assertTrue(payload)
        first, second = self.me_calls()
        self.assertIn("Pulse.Auth.Cookie=stale", first)
        self.assertIn("Pulse.Auth.Cookie=fresh", second)
        self.assertNotIn("stale", second, "the rejected cookie is not sent next to the new one")
        self.assertEqual(cookies["Pulse.Auth.Cookie"], "fresh", "the caller gets the renewed cookie to store")

    async def test_legacy_cookie_is_replaced(self):
        self.login_answers = [self.renewed_cookie()]
        cookies = {".AspNetCore.Cookies": "old", "KEYCLOAK_IDENTITY": "id"}
        payload, err = await self.call(cookies)
        self.assertIsNone(err)
        self.assertNotIn(".AspNetCore.Cookies", self.me_calls()[-1])
        self.assertNotIn(".AspNetCore.Cookies", cookies)

    async def test_dead_sso_session_reports_expiry_once_and_is_remembered(self):
        self.login_answers = [httpx.Response(302, headers={"Location": "https://sso.mirea.ru/realms/mirea/protocol/openid-connect/auth"})]
        cookies = {"Pulse.Auth.Cookie": "stale", "KEYCLOAK_IDENTITY": "id"}
        payload, err = await self.call(cookies)
        self.assertEqual((payload, err), (None, EXPIRED))
        self.assertEqual(len(self.me_calls()), 1, "no repeat without a renewed session")
        self.assertIn("__pulse_bootstrap_failed_at", cookies)
        self.refresh.assert_awaited()


if __name__ == "__main__":
    unittest.main()
