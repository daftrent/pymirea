"""
Сервис отметки посещаемости МИРЭА.

QR-код содержит URL вида:
https://pulse.mirea.ru/selfapprove?token=UUID

Отметка выполняется через gRPC-Web API «Пульса» (pulse.mirea.ru). HTML-страница
/selfapprove с конца сентября 2026 отдаёт только оболочку веб-приложения, поэтому
запасного пути через неё больше нет (см. CHANGELOG 0.5.0).
"""
import json
import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

import httpx

from ._http import make_async_client
from ._settings import settings
from .tokens import try_refresh_tokens


@dataclass
class AttendanceResult:
    success: bool
    message: str
    user_name: str | None = None


class MireaAPI:
    BASE_URL = "https://pulse.mirea.ru"
    SSO_URL = "https://sso.mirea.ru"
    SELFAPPROVE_ENDPOINT = "/selfapprove"

    def __init__(self, session_cookies: dict | None = None):
        """
        Args:
            session_cookies: Сохранённые cookies для авторизации
        """
        self.session_cookies = session_cookies or {}
        # Do not send internal session fields (tokens, local state) as HTTP cookies.
        cookies = httpx.Cookies()
        for name, value in self.session_cookies.items():
            if name in {"access_token", "token_type", "refresh_token", "expires_in"}:
                continue
            if name.startswith("__"):
                continue
            cookies.set(name, value, domain=".mirea.ru")
        limits = httpx.Limits(max_connections=100, max_keepalive_connections=50, keepalive_expiry=10.0)
        self.client = make_async_client(
            follow_redirects=True,
            timeout=httpx.Timeout(30.0, connect=10.0),
            cookies=cookies,
            transport=httpx.AsyncHTTPTransport(retries=2, limits=limits),
            proxy=settings.mirea_proxy if settings.mirea_proxy else None,
        )

    # Допустимые домены для QR-кодов посещаемости
    ALLOWED_DOMAINS = [
        "pulse.mirea.ru",
        "attendance-app.mirea.ru",
        "attendance.mirea.ru",
        "att.mirea.ru",
    ]

    @staticmethod
    def extract_token_from_qr(qr_data: str) -> tuple[str | None, str | None]:
        """
        Извлечь токен из данных QR-кода

        Args:
            qr_data: URL из QR-кода (https://pulse.mirea.ru/selfapprove?token=...)

        Returns:
            Кортеж (токен, ошибка) - токен если успешно, иначе ошибка
        """
        try:
            qr_data = qr_data.strip()

            # Если это просто токен (UUID)
            if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', qr_data, re.I):
                return qr_data, None

            # Если это URL (схема может отсутствовать)
            candidate_url = None
            if qr_data.startswith("http"):
                candidate_url = qr_data
            else:
                # Часто QR может содержать URL без схемы
                lower = qr_data.lower()
                if any(host in lower for host in MireaAPI.ALLOWED_DOMAINS):
                    candidate_url = "https://" + qr_data.lstrip("/")

            if candidate_url:
                parsed = urlparse(candidate_url)
                host = (parsed.hostname or "").lower()

                # Проверяем что домен принадлежит MIREA (учитываем возможный порт)
                if host not in MireaAPI.ALLOWED_DOMAINS:
                    return None, "Неверный QR-код. Ожидается код посещаемости МИРЭА."

                params = parse_qs(parsed.query)
                token = params.get("token", [None])[0]
                if not token:
                    return None, "QR-код не содержит токен посещаемости"
                return token, None

            return None, "Неверный формат QR-кода"
        except Exception:
            return None, "Ошибка обработки QR-кода"

    async def get_attendance_score(self) -> float | None:
        """
        Получить текущий балл посещаемости через grades API.
        Возвращает сумму баллов attendance по всем предметам или None при ошибке.
        """
        try:
            from .grades import MireaGrades
            grades_api = MireaGrades(self.session_cookies)
            result = await grades_api.get_grades()
            await grades_api.close()

            if result.success and result.subjects:
                # Суммируем баллы посещаемости по всем предметам
                total_attendance = sum(s.attendance for s in result.subjects)
                return total_attendance
            return None
        except Exception:
            return None

    async def _mark_attendance_via_grpc(
        self,
        token: str,
    ) -> AttendanceResult:
        """
        Self-approve through the Pulse gRPC-Web API, the only attendance endpoint the
        university still serves. Always returns a result with the real reason.
        """
        import logging
        logger = logging.getLogger(__name__)
        try:
            from .grades import MireaGrades
            grades_api = MireaGrades(self.session_cookies)
            try:
                approved, message = await grades_api.self_approve_attendance(token)
                # Persist any refreshed cookies and tokens (Pulse.Auth.Cookie, access_token).
                self.session_cookies.update(grades_api.session_cookies)
            finally:
                await grades_api.close()
        except Exception as e:
            logger.warning(f"gRPC self-approve failed: {e}")
            return AttendanceResult(
                success=False,
                message="МИРЭА временно недоступна. Попробуйте ещё раз.",
            )

        if approved is True:
            return AttendanceResult(
                success=True,
                message="Посещаемость отмечена",
            )

        if approved is False:
            return AttendanceResult(
                success=False,
                message=message or "Отметка пока недоступна",
            )

        # approved is None: the session expired, the upstream is unavailable or answered an error.
        logger.info(f"gRPC self-approve unclear: {message}")
        return AttendanceResult(
            success=False,
            message=message or "Не удалось отметиться. Попробуйте ещё раз.",
        )

    async def mark_attendance(self, qr_data: str, *, _refreshed: bool = False) -> AttendanceResult:
        """
        Отметить посещаемость по данным из QR-кода
        """
        token, error = self.extract_token_from_qr(qr_data)
        if not token:
            return AttendanceResult(
                success=False,
                message=error or "Не удалось извлечь токен из QR-кода"
            )

        refreshed_before = self.session_cookies.get("__token_refreshed_at")
        grpc_result = await self._mark_attendance_via_grpc(token)
        # If upstream says the session expired, try the refresh-token flow once. The gRPC call
        # refreshes by itself on HTTP 401; do not repeat it when that already happened.
        msg = (grpc_result.message or "").lower()
        looks_expired = ("перелог" in msg) or ("сессия истек" in msg) or ("needs_auth" in msg)
        already_refreshed = self.session_cookies.get("__token_refreshed_at") != refreshed_before
        if (not grpc_result.success) and (not _refreshed) and looks_expired and not already_refreshed:
            if await try_refresh_tokens(self.session_cookies):
                return await self._mark_attendance_via_grpc(token)
        return grpc_result

    async def mark_attendance_for_group(
        self,
        qr_data: str,
        users_sessions: list[tuple[int, str, dict]]  # [(user_id, name, cookies), ...]
    ) -> list[AttendanceResult]:
        """
        Отметить посещаемость для группы пользователей

        Args:
            qr_data: URL или токен из QR-кода
            users_sessions: Список кортежей (user_id, user_name, session_cookies)

        Returns:
            Список результатов для каждого пользователя
        """
        results = []
        token, error = self.extract_token_from_qr(qr_data)

        if not token:
            return [AttendanceResult(
                success=False,
                message=error or "Не удалось извлечь токен из QR-кода"
            )]

        for user_id, user_name, cookies in users_sessions:
            api = MireaAPI(session_cookies=cookies)
            try:
                result = await api.mark_attendance(qr_data)
                result.user_name = user_name
                results.append(result)
            except Exception:
                results.append(AttendanceResult(
                    success=False,
                    message="Ошибка отметки",
                    user_name=user_name
                ))
            finally:
                await api.close()

        return results

    def export_cookies(self) -> str:
        """Экспортировать cookies в JSON для сохранения в БД"""
        return json.dumps(dict(self.client.cookies))

    @staticmethod
    def import_cookies(cookies_json: str) -> dict:
        """Импортировать cookies из JSON"""
        try:
            return json.loads(cookies_json)
        except Exception:
            return {}

    async def close(self):
        await self.client.aclose()
