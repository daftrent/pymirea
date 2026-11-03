"""Integration tests for MireaAuth.login — full Keycloak SSO flow + 2FA detection."""

from __future__ import annotations

import base64
import secrets

import httpx
import pytest
import respx

from pymirea import Config, MireaAuth, configure


def _setup() -> None:
    configure(Config(session_keys=base64.b64encode(secrets.token_bytes(32)).decode()))


AUTH_URL = "https://sso.mirea.ru/realms/mirea/protocol/openid-connect/auth"
TOKEN_URL = "https://sso.mirea.ru/realms/mirea/protocol/openid-connect/token"
LOGIN_ACTION_BASE = "https://sso.mirea.ru/realms/mirea/login-actions/authenticate"
LOGIN_ACTION = f"{LOGIN_ACTION_BASE}?session_code=SC&execution=EX&client_id=attendance-app&tab_id=T1"


def _kc_login_form(action_url: str = LOGIN_ACTION) -> str:
    escaped = action_url.replace("&", "\\u0026")
    return (
        '<html><body><script>'
        f'var kcContext = {{"loginAction": "{escaped}", "pageId": "login-username"}};'
        '</script></body></html>'
    )


def _kc_email_code_form(action_url: str) -> str:
    escaped = action_url.replace("&", "\\u0026")
    return (
        '<script>'
        f'var kcContext = {{"loginAction": "{escaped}", "pageId": "email-code-form"}};'
        '</script>'
    )


def _kc_otp_form(action_url: str) -> str:
    escaped = action_url.replace("&", "\\u0026")
    return (
        '<script>'
        f'var kcContext = {{"loginAction": "{escaped}", "pageId": "otp-form", "otpLogin": {{}}}};'
        '</script>'
    )






@pytest.mark.asyncio
async def test_login_empty_username_returns_failure():
    _setup()
    auth = MireaAuth()
    try:
        result = await auth.login("", "pw")
    finally:
        await auth.close()
    assert result.success is False


@pytest.mark.asyncio
async def test_login_empty_password_returns_failure():
    _setup()
    auth = MireaAuth()
    try:
        result = await auth.login("user", "")
    finally:
        await auth.close()
    assert result.success is False






@pytest.mark.asyncio
@respx.mock
async def test_login_wrong_credentials_returns_failure():
    _setup()
    # Keycloak renders a page that stays on login-actions (not a redirect away)
    # and contains an error message in kcContext.
    err_html = (
        '<script>var kcContext = {"loginAction":"'
        + LOGIN_ACTION.replace("&", "\\u0026")
        + '","pageId":"login-username","message":"Invalid username or password"};</script>'
    )
    respx.get(AUTH_URL).mock(return_value=httpx.Response(200, text=_kc_login_form()))
    respx.post(LOGIN_ACTION_BASE).mock(return_value=httpx.Response(200, text=err_html))

    auth = MireaAuth()
    try:
        result = await auth.login("ivanov", "wrong")
    finally:
        await auth.close()

    assert result.success is False
    assert result.challenge is None


@pytest.mark.asyncio
@respx.mock
async def test_login_missing_login_action_returns_failure():
    _setup()
    respx.get(AUTH_URL).mock(return_value=httpx.Response(200, text="<html>no kcContext</html>"))

    auth = MireaAuth()
    try:
        result = await auth.login("x", "y")
    finally:
        await auth.close()

    assert result.success is False
