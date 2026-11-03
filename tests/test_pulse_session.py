"""Pulse session helpers (Pulse.Auth.Cookie since 2026-10-06). Offline, no network."""
import httpx

from pymirea.grades import MireaGrades
from pymirea.pulse_session import (
    BOOTSTRAP_FAILED_AT_KEY,
    PULSE_LOGIN_PARAMS,
    has_pulse_auth_cookie,
    is_keycloak_flow_cookie,
    is_pulse_auth_cookie,
    pulse_issued_cookies,
    pulse_session_needs_login,
)


def test_both_cookie_names_and_their_chunks_count():
    for name in ("Pulse.Auth.Cookie", "Pulse.Auth.CookieC2", ".AspNetCore.Cookies", ".AspNetCore.CookiesC1"):
        assert is_pulse_auth_cookie(name), name
    for name in ("Pulse.Auth.CookieX", ".AspNetCore.Correlation.abc", "KEYCLOAK_IDENTITY", ""):
        assert not is_pulse_auth_cookie(name), name
    assert is_pulse_auth_cookie("Pulse.Auth.Cookie", "Pulse.Auth.Cookie")
    assert not is_pulse_auth_cookie(".AspNetCore.Cookies", "Pulse.Auth.Cookie")


def test_has_cookie_needs_a_value():
    assert has_pulse_auth_cookie({"Pulse.Auth.Cookie": "x"})
    assert has_pulse_auth_cookie({".AspNetCore.Cookies": "x"})
    assert not has_pulse_auth_cookie({"Pulse.Auth.Cookie": ""})
    assert not has_pulse_auth_cookie(None)


def test_keycloak_flow_cookies_are_not_session_cookies():
    for name in ("AUTH_SESSION_ID", "AUTH_SESSION_ID_LEGACY", "KC_RESTART", "KC_AUTH_SESSION_HASH"):
        assert is_keycloak_flow_cookie(name), name
    for name in ("KEYCLOAK_IDENTITY", "KEYCLOAK_SESSION", "Pulse.Auth.Cookie"):
        assert not is_keycloak_flow_cookie(name), name


def test_only_cookies_issued_by_pulse_count_as_fresh():
    jar = httpx.Cookies()
    jar.set("Pulse.Auth.Cookie", "restored", domain=".mirea.ru")
    jar.set("Pulse.Auth.Cookie", "fresh", domain="pulse.mirea.ru")
    jar.set(".AspNetCore.Correlation.x", "c", domain="pulse.mirea.ru")
    jar.set(".AspNetCore.OpenIdConnect.Nonce.x", "n", domain="pulse.mirea.ru")
    jar.set("__ddg1_", "d", domain="pulse.mirea.ru")
    jar.set("KEYCLOAK_IDENTITY", "k", domain="sso.mirea.ru")
    assert pulse_issued_cookies(jar) == {"Pulse.Auth.Cookie": "fresh"}


def test_dead_session_marker():
    assert not pulse_session_needs_login({"Pulse.Auth.Cookie": "x"})
    assert pulse_session_needs_login({BOOTSTRAP_FAILED_AT_KEY: 1})
    assert not pulse_session_needs_login(None)


def test_login_asks_pulse_to_remember_the_session():
    assert PULSE_LOGIN_PARAMS == {"redirectUri": "https://pulse.mirea.ru/", "rememberMe": "True"}


def test_historical_bootstrap_name_still_works():
    assert MireaGrades._ensure_aspnet_cookie is MireaGrades._ensure_pulse_cookie
