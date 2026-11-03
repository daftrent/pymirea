"""
What a Pulse (pulse.mirea.ru) session looks like in a stored MIREA session.

Shared by the auth, grades and API layers; keep it free of service imports.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

# Pulse keeps its server-side session in this httpOnly cookie (renamed from
# `.AspNetCore.Cookies` on 2026-10-06; ASP.NET may split a long value into `...C1`, `...C2`).
PULSE_AUTH_COOKIE = "Pulse.Auth.Cookie"
LEGACY_PULSE_AUTH_COOKIE = ".AspNetCore.Cookies"
PULSE_AUTH_COOKIE_NAMES = (PULSE_AUTH_COOKIE, LEGACY_PULSE_AUTH_COOKIE)
PULSE_HOST = "pulse.mirea.ru"
PULSE_LOGIN_URL = "https://pulse.mirea.ru/api/auth/login"
# Where Pulse sends the browser after login; the web app asks for its own root.
# rememberMe=True is what the web app sends when "remember me" is ticked: Pulse and
# Keycloak then keep the session longer than the 16-hour default.
PULSE_LOGIN_REDIRECT = "https://pulse.mirea.ru/"
PULSE_LOGIN_PARAMS = {"redirectUri": PULSE_LOGIN_REDIRECT, "rememberMe": "True"}
# Session key (never sent as a cookie: `__` prefix) with the time of the last failed bootstrap.
BOOTSTRAP_FAILED_AT_KEY = "__pulse_bootstrap_failed_at"
BOOTSTRAP_RETRY_AFTER_S = 30 * 60
SESSION_EXPIRED_MESSAGE = "Сессия МИРЭА истекла. Перелогиньтесь."


def is_pulse_auth_cookie(name: str, *bases: str) -> bool:
    """True for a Pulse auth cookie or one of its chunks (`<name>C1`, `<name>C2`, ...)."""
    name = name or ""
    for base in bases or PULSE_AUTH_COOKIE_NAMES:
        if name == base or re.fullmatch(re.escape(base) + r"C\d+", name):
            return True
    return False


def is_keycloak_flow_cookie(name: str) -> bool:
    """Keycloak cookies that belong to one login attempt, not to the SSO session."""
    return name.startswith("AUTH_SESSION_ID") or name.startswith("KC_")


def has_pulse_auth_cookie(cookies: Mapping | None) -> bool:
    return any(is_pulse_auth_cookie(str(name)) and value for name, value in dict(cookies or {}).items())


def pulse_issued_cookies(jar) -> dict[str, str]:
    """
    Cookies that pulse.mirea.ru itself set during this client's requests.

    `jar` is an `httpx.Cookies`. Stored session cookies are loaded for `.mirea.ru`, so a
    host-only cookie for `pulse.mirea.ru` is always a fresh one from the upstream. OIDC
    bookkeeping (nonce, correlation) and DDoS-Guard cookies are not session state.
    """
    fresh: dict[str, str] = {}
    for cookie in jar.jar:
        if (cookie.domain or "").lstrip(".").lower() != PULSE_HOST:
            continue
        name = cookie.name or ""
        if name.startswith("__") or name.startswith(".AspNetCore.Correlation") or name.startswith(".AspNetCore.OpenIdConnect"):
            continue
        fresh[name] = cookie.value or ""
    return fresh


def pulse_session_needs_login(cookies: Mapping | None) -> bool:
    """
    True once a bootstrap has proved the stored session dead (SSO showed its login
    form, looped, or issued no cookie): only a new login by the user can help.
    """
    return bool(dict(cookies or {}).get(BOOTSTRAP_FAILED_AT_KEY))
