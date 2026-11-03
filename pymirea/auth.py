"""
Сервис авторизации через SSO МИРЭА

Авторизация происходит через login.mirea.ru с учётными данными студента.
После успешного входа сохраняются cookies для дальнейших запросов.
"""
import base64
import hashlib
import logging
import re
import secrets
from dataclasses import dataclass, replace
from urllib.parse import parse_qs, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from ._http import make_async_client
from ._settings import settings
from .pulse_session import PULSE_LOGIN_PARAMS, PULSE_LOGIN_URL, has_pulse_auth_cookie
from .upstreams import get_breaker

logger = logging.getLogger(__name__)

@dataclass
class AuthChallenge:
    kind: str  # "otp"
    action_url: str
    field_name: str
    hidden_fields: dict[str, str]
    referer: str | None = None
    # Used for OAuth2 code -> token exchange (PKCE).
    pkce_verifier: str | None = None
    redirect_uri: str | None = None
    # Preserve host/path scope across OTP in the server-side pending challenge.
    pulse_cookies: list[dict] | None = None


@dataclass
class AuthResult:
    success: bool
    message: str
    cookies: dict | None = None
    user_info: dict | None = None
    challenge: AuthChallenge | None = None

    @property
    def tokens(self) -> dict | None:
        """Alias for ``cookies`` — name used in README/examples."""
        return self.cookies


class MireaAuth:
    """Авторизация через SSO МИРЭА"""

    LOGIN_URL = "https://login.mirea.ru"
    SSO_URL = "https://sso.mirea.ru"
    ATTENDANCE_URL = "https://pulse.mirea.ru"
    ATTENDANCE_API_URL = "https://pulse.mirea.ru"
    TOKEN_URL = "https://sso.mirea.ru/realms/mirea/protocol/openid-connect/token"
    CLIENT_ID = "attendance-app"

    def __init__(self):
        self._headers = {
            "User-Agent": "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
        }
        limits = httpx.Limits(max_connections=100, max_keepalive_connections=50, keepalive_expiry=10.0)
        timeout = httpx.Timeout(30.0, connect=10.0)
        # Основной клиент для SSO
        self.client = make_async_client(
            follow_redirects=True,
            timeout=timeout,
            headers=self._headers,
            transport=httpx.AsyncHTTPTransport(retries=2, limits=limits),
            proxy=settings.mirea_proxy if settings.mirea_proxy else None,
        )
        # Клиент с прокси для pulse.mirea.ru (блокирует датацентры)
        self.proxy_client = make_async_client(
            follow_redirects=True,
            timeout=timeout,
            headers=self._headers,
            transport=httpx.AsyncHTTPTransport(retries=2, limits=limits),
            proxy=settings.mirea_proxy if settings.mirea_proxy else None,
        ) if settings.mirea_proxy else None
        if self.proxy_client:
            # Держим куки в синхроне, чтобы можно было повторить запросы через прокси
            self.proxy_client.cookies.update(self.client.cookies)

    @staticmethod
    def _generate_pkce_verifier() -> str:
        # RFC 7636: verifier length 43..128 chars. token_urlsafe(64) is usually ~86 chars.
        return secrets.token_urlsafe(64)

    @staticmethod
    def _pkce_challenge(verifier: str) -> str:
        digest = hashlib.sha256(verifier.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    @staticmethod
    def _extract_code_from_url(url: str) -> str | None:
        try:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            code = (qs.get("code") or [None])[0]
            return str(code) if code else None
        except (ValueError, AttributeError):
            return None

    async def _exchange_code_for_token(self, code: str, *, code_verifier: str | None, redirect_uri: str) -> dict | None:
        """
        Exchange OAuth2 authorization code for Keycloak tokens.

        Returns dict with access_token/refresh_token/token_type/expires_in on success, else None.
        """
        if not code:
            return None
        data: dict[str, str] = {
            "grant_type": "authorization_code",
            "client_id": self.CLIENT_ID,
            "redirect_uri": redirect_uri,
            "code": code,
        }
        if code_verifier:
            data["code_verifier"] = code_verifier

        try:
            breaker = get_breaker("mirea_sso")
            decision = await breaker.allow()
            if not decision.allowed:
                return None
            resp = await self.client.post(
                self.TOKEN_URL,
                data=data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                },
            )
            if resp.status_code != 200:
                if 500 <= int(resp.status_code) <= 599:
                    await breaker.record_failure()
                else:
                    await breaker.record_success()
                logger.warning("Token exchange failed: %s", resp.status_code)
                return None
            body = resp.json()
            if not isinstance(body, dict):
                await breaker.record_success()
                return None
            if not body.get("access_token"):
                await breaker.record_success()
                return None
            await breaker.record_success()
            return {
                "access_token": body.get("access_token"),
                "token_type": body.get("token_type", "Bearer"),
                "refresh_token": body.get("refresh_token"),
                "expires_in": body.get("expires_in"),
            }
        except (httpx.NetworkError, httpx.TimeoutException, httpx.HTTPError) as e:
            logger.warning("Token exchange network error: %s", type(e).__name__)
            try:
                await get_breaker("mirea_sso").record_failure()
            except Exception:
                pass
            return None
        except (ValueError, KeyError) as e:
            logger.warning("Token exchange response error: %s", type(e).__name__)
            return None

    async def refresh_tokens(self, refresh_token: str) -> dict | None:
        """
        Refresh Keycloak tokens using refresh_token grant.

        Returns dict with access_token/refresh_token/token_type/expires_in on success, else None.
        """
        token = (refresh_token or "").strip()
        if not token:
            return None

        data: dict[str, str] = {
            "grant_type": "refresh_token",
            "client_id": self.CLIENT_ID,
            "refresh_token": token,
        }

        breaker = get_breaker("mirea_sso")
        decision = await breaker.allow()
        if not decision.allowed:
            return None

        try:
            resp = await self.client.post(
                self.TOKEN_URL,
                data=data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                },
            )
            if resp.status_code != 200:
                if 500 <= int(resp.status_code) <= 599:
                    await breaker.record_failure()
                else:
                    await breaker.record_success()
                logger.warning("Token refresh failed: %s", resp.status_code)
                return None

            body = resp.json()
            if not isinstance(body, dict):
                await breaker.record_success()
                return None

            access = body.get("access_token")
            if not access:
                await breaker.record_success()
                return None

            await breaker.record_success()
            return {
                "access_token": access,
                "token_type": body.get("token_type", "Bearer"),
                # Some Keycloak setups may omit refresh_token on refresh.
                "refresh_token": body.get("refresh_token") or token,
                "expires_in": body.get("expires_in"),
            }
        except (httpx.NetworkError, httpx.TimeoutException, httpx.HTTPError) as e:
            logger.warning("Token refresh network error: %s", type(e).__name__)
            try:
                await breaker.record_failure()
            except Exception as e2:
                logger.debug("Breaker record_failure failed: %s", e2)
            return None
        except (ValueError, KeyError) as e:
            # JSON decode or unexpected response shape
            logger.warning("Token refresh response error: %s", type(e).__name__)
            try:
                await breaker.record_success()  # Server responded, just bad data
            except Exception:
                pass
            return None

    @staticmethod
    def _pulse_url(url: str) -> bool:
        parsed = urlparse(url)
        return (parsed.scheme == "https" and parsed.hostname in {"pulse.mirea.ru", "sso.mirea.ru"}
                and parsed.port in (None, 443) and not parsed.username and not parsed.password)

    async def _pulse_request(self, method: str, url: str, *, data=None, referer=None):
        # Follow the browser flow, but never forward a password/OTP to a redirect.
        for _ in range(12):
            if not self._pulse_url(url):
                raise ValueError("Unexpected authentication destination")
            response = await self.client.request(method, url, data=data,
                headers={"Referer": referer} if referer else {}, follow_redirects=False)
            if response.status_code not in (301, 302, 303, 307, 308):
                return response
            if not response.headers.get("location"):
                raise ValueError("Missing authentication redirect")
            if method == "POST" and response.status_code in (307, 308):
                raise ValueError("Refusing to replay authentication form")
            referer, url = str(response.url), urljoin(str(response.url), response.headers["location"])
            method, data = "GET", None
        raise ValueError("Too many authentication redirects")

    def _pulse_cookie_state(self) -> list[dict]:
        return [{"name": c.name, "value": c.value, "domain": c.domain, "path": c.path,
                 "secure": c.secure, "expires": c.expires} for c in self.client.cookies.jar]

    def _restore_pulse_cookies(self, cookies: list[dict]):
        for item in cookies:
            self.client.cookies.set(item["name"], item["value"], domain=item["domain"], path=item["path"])
        for cookie in self.client.cookies.jar:
            saved = next(c for c in cookies if (c["name"], c["domain"], c["path"]) ==
                         (cookie.name, cookie.domain, cookie.path))
            cookie.secure, cookie.expires = saved["secure"], saved["expires"]

    def _pulse_session_cookies(self) -> dict:
        # Flatten only after the OAuth callback; prefer specific domain/path cookies.
        result = {}
        for cookie in sorted(self.client.cookies.jar, key=lambda c: (len(c.domain or ""), len(c.path or ""))):
            if not cookie.is_expired():
                result[cookie.name] = cookie.value
        return result

    async def _pulse_result(self, response) -> AuthResult:
        skipped_max_enrollment = False
        for _ in range(5):
            if response.status_code != 200:
                return AuthResult(False, "Сервер МИРЭА временно недоступен. Попробуйте позже.")
            if response.url.host == "pulse.mirea.ru":
                cookies = self._pulse_session_cookies()
                if has_pulse_auth_cookie(cookies):
                    # Telegram identity is verified by the caller; Pulse completed its OAuth callback.
                    return AuthResult(True, "Авторизация успешна", cookies=cookies)
                return AuthResult(False, "Не удалось получить сессию Пульса. Начните вход заново.")
            callback = self._extract_pulse_callback_form(response.text)
            if callback:
                # Since 26.10.2026 Pulse asks for response_mode=form_post: a finished login is
                # an auto-submitting form that hands the one-use code to Pulse, not a redirect.
                action, fields = callback
                response = await self._pulse_request("POST", action, data=fields, referer=str(response.url))
                continue
            challenge = self._extract_otp_challenge(response.text, base_url=str(response.url))
            page_id = self._keycloak_page_id(response.text)
            # Fixed labels only: no HTML, URLs, codes, cookie values or user data.
            diagnostic_page = page_id if page_id in {
                "login-otp", "login-max-otp", "email-code-form", "qr-login",
                "max-account-config", "login-page-expired", "select-authenticator", "error",
            } else "other"
            enrollment = bool(re.search(r'"isEnrollment"\s*:\s*true', response.text))
            can_skip = bool(re.search(r'"showSkip"\s*:\s*true', response.text))
            phone_unregistered = bool(re.search(r'"phoneNotRegistered"\s*:\s*true', response.text))
            phone_missing = bool(re.search(r'"noPhoneNumber"\s*:\s*true', response.text))
            delivery_pending = bool(re.search(r'"deliveryPending"\s*:\s*true', response.text))
            send_failed = bool(re.search(r'"sendFailed"\s*:\s*true', response.text))
            # The service intentionally has no INFO/access log; keep this bounded
            # diagnostic visible while a login is still awaiting confirmation.
            logger.warning("Pulse auth form: page=%s challenge=%s enrollment=%s skip_offered=%s "
                           "phone_unregistered=%s phone_missing=%s delivery_pending=%s send_failed=%s",
                        diagnostic_page, challenge.kind if challenge else "none", enrollment, can_skip,
                        phone_unregistered, phone_missing, delivery_pending, send_failed)
            if page_id == "login-max-otp" and (enrollment or phone_unregistered or phone_missing):
                # The SSO UI offers Skip for enrollment AND for an absent/unregistered
                # phone, even when isEnrollment=false. Delivery states take precedence
                # in that UI and do not display Skip. Never skip an actual MAX OTP.
                action = self._extract_login_action(response.text)
                if not can_skip or delivery_pending or send_failed or not action or skipped_max_enrollment:
                    return AuthResult(False, "Завершите настройку аккаунта на сайте Пульса и повторите вход.")
                skipped_max_enrollment = True
                response = await self._pulse_request("POST", action, data={"skip": "true"},
                                                     referer=str(response.url))
                continue
            if challenge:
                if not self._pulse_url(challenge.action_url):
                    raise ValueError("Unexpected challenge destination")
                challenge.referer = str(response.url)
                challenge.pulse_cookies = self._pulse_cookie_state()
                return AuthResult(False, "Введите код подтверждения.", challenge=challenge)
            # Retain the existing optional MAX enrollment skip. Never complete
            # unknown required actions (password change, consent, credential setup).
            page = re.search(r'"pageId"\s*:\s*"([^"\n]+)"', response.text)
            if page and page.group(1) in {"max-account-config", "max-account-config.ftl"}:
                action = self._extract_login_action(response.text)
                if action:
                    response = await self._pulse_request("POST", action, data={"skip": "true"},
                                                         referer=str(response.url))
                    continue
            return AuthResult(False, "Не удалось войти. Проверьте данные и повторите попытку.")
        return AuthResult(False, "Завершите настройку аккаунта на сайте Пульса и повторите вход.")

    async def login(self, username: str, password: str) -> AuthResult:
        # Pulse owns PAR, PKCE and the one-use code exchange. Starting a direct
        # attendance-app authorization request now fails before the password form.
        breaker = get_breaker("mirea_sso")
        try:
            if not (await breaker.allow()).allowed:
                return AuthResult(False, "МИРЭА временно недоступна. Попробуйте позже.")
            start_url = str(httpx.URL(PULSE_LOGIN_URL, params=PULSE_LOGIN_PARAMS))
            page = await self._pulse_request("GET", start_url)
            if page.status_code >= 500:
                await breaker.record_failure()
            else:
                await breaker.record_success()
            action = self._extract_login_action(page.text) if page.status_code == 200 else None
            if page.url.host != "sso.mirea.ru" or not action:
                return AuthResult(False, "Не удалось получить форму входа МИРЭА. Попробуйте позже.")
            response = await self._pulse_request("POST", action,
                # rememberMe asks Keycloak for its longer "remember me" SSO session instead of
                # the 16-hour default that made every stored session die within a day or two.
                data={"username": username, "password": password, "credentialId": "", "rememberMe": "on"},
                referer=str(page.url))
            return await self._pulse_result(response)
        except httpx.TimeoutException:
            await breaker.record_failure()
            return AuthResult(False, "Сервер МИРЭА не отвечает")
        except Exception:
            # Never return upstream exceptions: URLs can contain OAuth secrets.
            return AuthResult(False, "Не удалось выполнить вход МИРЭА. Попробуйте позже.")

    async def _submit_pulse_otp(self, challenge: AuthChallenge, code: str) -> AuthResult:
        try:
            self._restore_pulse_cookies(challenge.pulse_cookies or [])
            payload = {**challenge.hidden_fields, challenge.field_name: code.strip()}
            if not payload[challenge.field_name]:
                return AuthResult(False, "Введите код подтверждения")
            response = await self._pulse_request("POST", challenge.action_url, data=payload,
                                                 referer=challenge.referer or challenge.action_url)
            return await self._pulse_result(response)
        except httpx.TimeoutException:
            return AuthResult(False, "Сервер МИРЭА не отвечает")
        except Exception:
            return AuthResult(False, "Не удалось подтвердить вход. Начните заново.")

    @staticmethod
    def _log_kc_context(html: str) -> None:
        """Log kcContext details for debugging OTP issues."""
        try:
            page_id = re.search(r'"pageId"\s*:\s*"([^"]+)"', html)
            if page_id:
                pass

            # Dump raw HTML around kcContext (first <script> block with pageId).
            # The kcContext is embedded as a JS object in a <script> tag.
            script_idx = html.find('"pageId"')
            if script_idx >= 0:
                # Go back to find the start of the script content
                start = max(0, script_idx - 200)
                chunk = html[start:start+5000].replace('\n', ' ').replace('\r', ' ')
                chunk = re.sub(r'\s+', ' ', chunk)

            # Log any message/error
            msg = re.search(r'"message"\s*:\s*"([^"]*)"', html)
            if msg:
                pass
        except Exception:
            pass

    def _extract_login_action(self, html: str) -> str | None:
        """Извлечь loginAction URL из kcContext JavaScript"""
        m = re.search(r'"loginAction"\s*:\s*"(https?://[^"]+)"', html)
        if m:
            # URL может содержать escaped символы
            return m.group(1).replace("\\u0026", "&").replace("\\/", "/")
        return None

    def _extract_keycloak_error(self, html: str) -> str | None:
        """Извлечь ошибку из kcContext"""
        m = re.search(r'"message"\s*:\s*"([^"]+)"', html)
        if m:
            msg = m.group(1)
            msg_l = msg.lower()
            # Keycloak can return generic "invalid" messages for both password and OTP.
            if "invalid" in msg_l:
                if any(x in msg_l for x in ("otp", "code", "authenticator", "однораз", "кода")):
                    return "Неверный код подтверждения"
                if any(x in msg_l for x in ("credential", "password", "парол")):
                    return "Неверный логин или пароль"
            return msg
        return None

    def _extract_pulse_callback_form(self, html: str) -> tuple[str, dict[str, str]] | None:
        """Keycloak form_post page: an auto-submitting form to Pulse's OAuth callback."""
        if '"pageId"' in html:
            return None
        form = BeautifulSoup(html, "html.parser").find("form", action=True)
        if not form or (form.get("method") or "").lower() != "post":
            return None
        action = form["action"].strip()
        # The code is only ever handed to Pulse itself, never to SSO or a foreign host.
        if not self._pulse_url(action) or urlparse(action).hostname != "pulse.mirea.ru":
            return None
        fields = {i["name"]: i.get("value") or "" for i in form.find_all("input") if i.get("name")}
        return (action, fields) if "code" in fields or "error" in fields else None

    @staticmethod
    def _keycloak_page_id(html: str) -> str | None:
        page = re.search(r'"pageId"\s*:\s*"([^"\n]+)"', html)
        return page.group(1).removesuffix(".ftl") if page else None

    def _extract_otp_challenge(self, html: str, *, base_url: str | None = None) -> AuthChallenge | None:
        """
        Detect Keycloak OTP step and extract form action + hidden fields.

        Supports both SPA (kcContext JavaScript) and classic HTML form pages.
        """
        try:
            # kcContext contains metadata for OTHER available authenticators too.
            # Only pageId identifies the currently displayed form; a global search
            # for "login-max-otp" can misclassify an email challenge as MAX.
            page_id = self._keycloak_page_id(html)
            formats = {
                "login-otp": ("otp", "otp", {}),
                "login-max-otp": ("otp", "code", {"login": "true"}),
                "email-code-form": ("email_code", "emailCode", {"login": "true"}),
            }
            selected = formats.get(page_id)
            # Retain support for old minimal contexts without a pageId at all.
            if page_id is None and re.search(r'"otpLogin"\s*:\s*(?:true|\{)', html):
                selected = formats["login-otp"]
            if selected:
                action_url = self._extract_login_action(html)
                if action_url:
                    kind, field_name, hidden_fields = selected
                    return AuthChallenge(kind=kind, action_url=action_url,
                                         field_name=field_name, hidden_fields=hidden_fields)

            # Fallback: classic HTML form parsing
            soup = BeautifulSoup(html, "html.parser")

            # Find the OTP form first (different Keycloak themes can rename the field).
            form = (
                soup.find("form", {"id": "kc-otp-login-form"})
                or soup.find("form", {"name": "kc-otp-login-form"})
            )
            if not form:
                # Heuristics: any form that contains an "one-time-code" field.
                for f in soup.find_all("form"):
                    if f.find("input", {"autocomplete": "one-time-code"}):
                        form = f
                        break

            # Fallback: look for an input that likely represents a 2FA/OTP code, then take its parent form.
            otp_input = None
            if not form:
                candidates = []
                for inp in soup.find_all("input"):
                    itype = (inp.get("type") or "").lower().strip()
                    name = (inp.get("name") or "").lower().strip()
                    iid = (inp.get("id") or "").lower().strip()
                    ac = (inp.get("autocomplete") or "").lower().strip()
                    im = (inp.get("inputmode") or "").lower().strip()

                    if itype in {"hidden", "submit", "button"}:
                        continue
                    if name in {"username", "password"} or iid in {"username", "password"}:
                        continue

                    # Strong indicators first.
                    score = 0
                    if ac == "one-time-code":
                        score += 10
                    if "otp" in name or "otp" in iid:
                        score += 8
                    if "totp" in name or "totp" in iid:
                        score += 8
                    if "code" in name or "code" in iid:
                        score += 6
                    if "token" in name or "token" in iid:
                        score += 4
                    if im in {"numeric", "tel"}:
                        score += 2
                    if itype in {"tel", "number"}:
                        score += 2
                    if score > 0:
                        candidates.append((score, inp))

                if candidates:
                    candidates.sort(key=lambda x: x[0], reverse=True)
                    otp_input = candidates[0][1]
                    form = otp_input.find_parent("form")

            if not form:
                return None

            # Determine the field name to POST.
            otp_field_name = None
            if not otp_input:
                for name in ("otp", "totp", "otpCode"):
                    otp_input = form.find("input", {"name": name}) or form.find("input", {"id": name})
                    if otp_input:
                        otp_field_name = otp_input.get("name") or name
                        break

            if not otp_field_name:
                # Pick first non-hidden input that isn't username/password.
                for inp in form.find_all("input"):
                    itype = (inp.get("type") or "").lower().strip()
                    if itype in {"hidden", "submit", "button"}:
                        continue
                    name = (inp.get("name") or "").strip()
                    if not name:
                        continue
                    if name.lower() in {"username", "password"}:
                        continue
                    otp_field_name = name
                    otp_input = inp
                    break

            if not otp_input or not otp_field_name:
                return None

            # Keycloak usually exposes a "loginAction" in kcContext as a full URL.
            action = self._extract_login_action(html) or (form.get("action") or "").strip()
            if not action:
                return None
            if base_url and action.startswith("/"):
                action = urljoin(base_url, action)
            if base_url and not action.startswith("http"):
                action = urljoin(base_url, action)

            hidden_fields: dict[str, str] = {}
            for inp in form.find_all("input"):
                try:
                    if (inp.get("type") or "").lower() != "hidden":
                        continue
                    name = (inp.get("name") or "").strip()
                    if not name:
                        continue
                    hidden_fields[name] = inp.get("value") or ""
                except Exception:
                    continue

            return AuthChallenge(
                kind="otp",
                action_url=action,
                field_name=otp_field_name,
                hidden_fields=hidden_fields,
            )
        except Exception:
            return None

    async def _handle_required_actions(self, start_url: str, *, referer: str, pkce_verifier: str | None, redirect_uri: str) -> AuthResult | None:
        """
        Handle Keycloak required-action pages (e.g. max-account-config).

        If the page contains an OTP/TOTP challenge, returns it as a new AuthChallenge
        for the user to complete. Otherwise attempts to skip or complete the action.

        Returns AuthResult on success/failure, or None if the URL is not a required-action.
        """
        url = start_url
        for attempt in range(5):  # max 5 required actions
            if "required-action" not in url:
                return None


            try:
                page_resp = await self.client.get(url, headers={"Referer": referer}, follow_redirects=False)
            except Exception as e:
                return None

            # If the required-action itself redirects (e.g., to the app with code), follow it.
            if page_resp.status_code in (302, 303, 307, 308):
                location = page_resp.headers.get("location", "")
                next_url = urljoin(str(page_resp.url), location)
                code = self._extract_code_from_url(next_url)
                if code:
                    all_cookies = dict(self.client.cookies)
                    tokens = await self._exchange_code_for_token(code, code_verifier=pkce_verifier, redirect_uri=redirect_uri)
                    if tokens:
                        all_cookies.update(tokens)
                    try:
                        await self.client.get(next_url, headers={"Referer": url}, follow_redirects=True)
                        all_cookies.update(dict(self.client.cookies))
                    except Exception:
                        pass
                    if all_cookies.get("access_token"):
                        return AuthResult(success=True, message="Авторизация успешна", cookies=all_cookies)
                # No code — keep following
                url = next_url
                referer = url
                continue

            # Got 200 — this is the required-action page HTML.
            html = page_resp.text
            self._log_kc_context(html)

            action_url = self._extract_login_action(html)
            if not action_url:
                return None

            # Try to skip/cancel the required action.
            # MIREA theme uses hidden input name="skip" value="true" in kc-max-otp-skip-form.
            orig_page_id_m = re.search(r'"pageId"\s*:\s*"([^"]+)"', html)
            orig_page_id = orig_page_id_m.group(1) if orig_page_id_m else None

            skip_payloads = [
                {"skip": "true"},
                {"cancel-aia": "true"},
            ]
            for payload in skip_payloads:
                try:
                    skip_resp = await self.client.post(
                        action_url,
                        data=payload,
                        headers={"Content-Type": "application/x-www-form-urlencoded", "Referer": str(page_resp.url)},
                        follow_redirects=False,
                    )
                except Exception as e:
                    continue

                if skip_resp.status_code in (302, 303, 307, 308):
                    location = skip_resp.headers.get("location", "")
                    next_url = urljoin(str(skip_resp.url), location)
                    code = self._extract_code_from_url(next_url)
                    if code:
                        all_cookies = dict(self.client.cookies)
                        tokens = await self._exchange_code_for_token(code, code_verifier=pkce_verifier, redirect_uri=redirect_uri)
                        if tokens:
                            all_cookies.update(tokens)
                        # Follow the redirect to pulse.mirea.ru to establish its session cookie
                        try:
                            await self.client.get(next_url, headers={"Referer": action_url}, follow_redirects=True)
                            all_cookies.update(dict(self.client.cookies))
                        except Exception:
                            pass
                        if all_cookies.get("access_token"):
                            return AuthResult(success=True, message="Авторизация успешна", cookies=all_cookies)
                        # Token exchange failed (confidential client), but we may have KC cookies.
                        # Try to bootstrap the Pulse auth cookie via pulse auth endpoint.
                        has_kc = any(k in all_cookies for k in ("KEYCLOAK_IDENTITY", "KEYCLOAK_SESSION"))
                        if has_kc:
                            try:
                                # Build a fresh client with only KC cookies needed for pulse auth
                                import httpx as _httpx
                                kc_cookie_names = ("KEYCLOAK_IDENTITY", "KEYCLOAK_SESSION")
                                cookie_header_parts = []
                                for cn in kc_cookie_names:
                                    cv = all_cookies.get(cn)
                                    if cv:
                                        cookie_header_parts.append(f"{cn}={cv}")
                                cookie_header = "; ".join(cookie_header_parts)
                                async with make_async_client(
                                    follow_redirects=True,
                                    timeout=_httpx.Timeout(15.0, connect=8.0),
                                    headers={
                                        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
                                        "Referer": "https://pulse.mirea.ru/",
                                        "Cookie": cookie_header,
                                    },
                                    transport=_httpx.AsyncHTTPTransport(retries=2),
                                ) as bootstrap_client:
                                    await bootstrap_client.get(PULSE_LOGIN_URL, params=PULSE_LOGIN_PARAMS)
                                    for name, value in bootstrap_client.cookies.items():
                                        all_cookies[name] = value
                                    # The Pulse auth cookie (`Pulse.Auth.Cookie`, formerly `.AspNetCore.Cookies`)
                                    # is now among all_cookies when the Keycloak session was accepted.
                            except Exception as e:
                                pass
                            return AuthResult(success=True, message="Авторизация успешна", cookies=all_cookies)
                    # Another redirect — might be another required-action or next step
                    url = next_url
                    referer = action_url
                    break  # break skip_payloads loop, continue outer loop
                else:
                    # Skip returned 200 — check if Keycloak advanced to a new page
                    # (some required actions render the next step inline instead of redirecting).
                    skip_html = skip_resp.text
                    skip_pid_m = re.search(r'"pageId"\s*:\s*"([^"]+)"', skip_html)
                    skip_page_id = skip_pid_m.group(1) if skip_pid_m else None

                    if skip_page_id and skip_page_id != orig_page_id:
                        if skip_page_id == "login-page-expired":
                            return None
                        # Page changed — extract challenge from the NEW page
                        self._log_kc_context(skip_html)
                        new_challenge = self._extract_otp_challenge(skip_html, base_url=str(skip_resp.url))
                        if new_challenge:
                            new_challenge.referer = str(skip_resp.url)
                            new_challenge.pkce_verifier = pkce_verifier
                            new_challenge.redirect_uri = redirect_uri
                            return AuthResult(
                                success=False,
                                message="Требуется код подтверждения (2FA)",
                                cookies=dict(self.client.cookies),
                                challenge=new_challenge,
                            )
                        # New page but no challenge — update and continue outer loop
                        new_action = self._extract_login_action(skip_html)
                        if new_action:
                            url = str(skip_resp.url)
                            referer = action_url
                            break  # continue outer loop with new page

                    continue
            else:
                # All skip approaches returned non-redirect — fall back to OTP challenge.
                otp_challenge = self._extract_otp_challenge(html, base_url=str(page_resp.url))
                if otp_challenge:
                    otp_challenge.referer = str(page_resp.url)
                    otp_challenge.pkce_verifier = pkce_verifier
                    otp_challenge.redirect_uri = redirect_uri
                    return AuthResult(
                        success=False,
                        message="Требуется код подтверждения (2FA)",
                        cookies=dict(self.client.cookies),
                        challenge=otp_challenge,
                    )
                return None
            continue  # continue outer loop after break from inner loop

        return None

    async def submit_otp(self, challenge: AuthChallenge, otp_code: str, *, cookies: dict | None = None) -> AuthResult:
        """
        Continue Keycloak login flow with an OTP code.

        `challenge` should be returned by `_extract_otp_challenge`.
        """
        # Also repair pending email challenges created before this form update.
        # MIREA's JS submit handler adds login=true; emailCode alone is not submitted as a login.
        if challenge.kind == "email_code" and challenge.field_name == "emailCode":
            challenge = replace(challenge, hidden_fields={**challenge.hidden_fields, "login": "true"})
        if challenge.pulse_cookies is not None:
            return await self._submit_pulse_otp(challenge, otp_code)
        # Pending challenges created before the PAR rollout retain their old flow.
        try:
            if cookies:
                self.client.cookies.update(cookies)
                if self.proxy_client:
                    self.proxy_client.cookies.update(self.client.cookies)

            payload = dict(challenge.hidden_fields or {})
            payload[challenge.field_name] = (otp_code or "").strip()

            if not payload[challenge.field_name]:
                return AuthResult(success=False, message="Введите код подтверждения")

            resp = await self.client.post(
                challenge.action_url,
                data=payload,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": challenge.referer or challenge.action_url,
                },
                follow_redirects=False,
            )

            if resp.status_code in (302, 303, 307, 308) and resp.headers.get("location"):
                location = resp.headers.get("location") or ""
                redirect_url = urljoin(str(resp.url), location)
                code = self._extract_code_from_url(redirect_url)
                redirect_uri = challenge.redirect_uri or f"{self.ATTENDANCE_URL}/"

                # Keycloak may redirect to a required-action page before issuing the code.
                if not code and "required-action" in redirect_url:
                    ra_result = await self._handle_required_actions(
                        redirect_url,
                        referer=challenge.action_url,
                        pkce_verifier=challenge.pkce_verifier,
                        redirect_uri=redirect_uri,
                    )
                    if ra_result:
                        return ra_result
                    # Could not skip — fall through to legacy handling.

                # Exchange authorization code BEFORE following redirect.
                # Keycloak codes are single-use; the redirect would consume it.
                all_cookies = dict(self.client.cookies)
                if code:
                    tokens = await self._exchange_code_for_token(
                        code,
                        code_verifier=challenge.pkce_verifier,
                        redirect_uri=redirect_uri,
                    )
                    if tokens:
                        all_cookies.update(tokens)

                # Now follow redirect to establish server-side session cookie.
                try:
                    await self.client.get(
                        redirect_url,
                        headers={"Referer": challenge.action_url},
                        follow_redirects=True,
                    )
                    all_cookies.update(dict(self.client.cookies))
                except Exception:
                    pass

                # Only declare success if we actually obtained tokens.
                if all_cookies.get("access_token"):
                    return AuthResult(success=True, message="Авторизация успешна", cookies=all_cookies)
                # We have cookies but no access_token — session is incomplete.
                has_session = any(k in all_cookies for k in ('KEYCLOAK_IDENTITY', 'KEYCLOAK_SESSION'))
                if has_session:
                    return AuthResult(success=True, message="Авторизация успешна", cookies=all_cookies)
                return AuthResult(success=False, message="Не удалось получить токены. Попробуйте войти заново.")

            final_url = str(resp.url)
            final_host = urlparse(final_url).hostname or ""
            if "login-actions" in final_url or final_host == "sso.mirea.ru":
                self._log_kc_context(resp.text)
                error_msg = self._extract_keycloak_error(resp.text)
                next_challenge = self._extract_otp_challenge(resp.text, base_url=final_url)
                if next_challenge:
                    next_challenge.referer = final_url
                    next_challenge.pkce_verifier = challenge.pkce_verifier
                    next_challenge.redirect_uri = challenge.redirect_uri
                    return AuthResult(
                        success=False,
                        message=error_msg or "Не удалось подтвердить вход (2FA)",
                        cookies=dict(self.client.cookies),
                        challenge=next_challenge,
                    )

                return AuthResult(success=False, message=error_msg or "Не удалось подтвердить вход (2FA)")

            all_cookies = dict(self.client.cookies)
            code = self._extract_code_from_url(final_url)
            if code and "access_token" not in all_cookies:
                redirect_uri = challenge.redirect_uri or f"{self.ATTENDANCE_URL}/"
                tokens = await self._exchange_code_for_token(
                    code,
                    code_verifier=challenge.pkce_verifier,
                    redirect_uri=redirect_uri,
                )
                if tokens:
                    all_cookies.update(tokens)
            if all_cookies:
                return AuthResult(success=True, message="Авторизация успешна", cookies=all_cookies)

            return AuthResult(success=False, message="Не удалось получить сессию")
        except httpx.TimeoutException:
            try:
                await get_breaker("mirea_sso").record_failure()
            except Exception:
                pass
            return AuthResult(success=False, message="Сервер МИРЭА не отвечает")
        except Exception as e:
            return AuthResult(success=False, message=f"Ошибка: {str(e)}")

    async def complete_2fa(self, challenge: AuthChallenge, code: str, *, cookies: dict | None = None) -> AuthResult:
        """Alias for :meth:`submit_otp` — name used in README/examples."""
        return await self.submit_otp(challenge, code, cookies=cookies)

    async def verify_session(self, cookies: dict) -> bool:
        """
        Проверить, активна ли сессия

        Args:
            cookies: Сохранённые cookies

        Returns:
            True если сессия активна
        """
        try:
            filtered_cookies = {}
            for name, value in (cookies or {}).items():
                if name in {"access_token", "token_type", "refresh_token", "expires_in"}:
                    continue
                if str(name).startswith("__"):
                    continue
                filtered_cookies[name] = value
            async with make_async_client(
                follow_redirects=True,
                timeout=httpx.Timeout(15.0, connect=8.0),
                cookies=filtered_cookies,
                transport=httpx.AsyncHTTPTransport(retries=2),
                proxy=settings.mirea_proxy if settings.mirea_proxy else None,
            ) as client:
                response = await client.get(self.ATTENDANCE_URL)

            # Если нас не редиректит на логин — сессия активна
            return "/login" not in str(response.url).lower()
        except (httpx.NetworkError, httpx.TimeoutException, httpx.HTTPError) as e:
            logger.debug("verify_session network error: %s", type(e).__name__)
            return False

    async def close(self):
        await self.client.aclose()
        if self.proxy_client:
            await self.proxy_client.aclose()
