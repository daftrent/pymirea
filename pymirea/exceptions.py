"""Typed exceptions for pymirea.

These exceptions are raised by NEW helpers introduced in 0.3.4
(e.g. :func:`pymirea.tokens.ensure_fresh_token`). Existing functions
(``try_refresh_tokens``, ``MireaAPI.mark_attendance`` etc.) keep their
historical contract — they still return ``None``/``False`` or raise
``httpx.*`` types as before. Nothing is rewired retroactively.

Consumers who want explicit error types can opt into the new helpers;
old call sites continue to work unchanged. Since 0.5.1 every result object
(``AttendanceResult``, ``GradesResult``, ``ScheduleResult``,
``AttendanceDetailResult``, ``AcsResult``) has ``raise_for_error(cookies)``,
which turns a failed result into one of these exceptions.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from .pulse_session import pulse_session_needs_login


class MireaError(Exception):
    """Base class for all pymirea-typed errors."""


class MireaSessionExpired(MireaError):
    """The session is unrecoverable without user re-authentication.

    Typically raised when a refresh attempt failed and there is no
    further automatic recovery possible (e.g. refresh_token itself
    expired or Keycloak rejected it).
    """


class MireaRefreshFailed(MireaError):
    """A refresh attempt failed transiently.

    The session may still be recoverable on retry — Keycloak might be
    flaky, the network might be slow, etc. Different from
    :class:`MireaSessionExpired` which signals a terminal state.
    """


class MireaRateLimited(MireaError):
    """Upstream returned 429. ``retry_after`` is the suggested wait in seconds."""

    def __init__(self, message: str = "rate limited", *, retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class MireaServerError(MireaError):
    """Upstream returned a 5xx response."""

    def __init__(self, message: str = "server error", *, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class MireaParseFailed(MireaError):
    """МИРЭА returned a response we could not parse.

    Usually means the upstream HTML/protobuf schema changed. The first
    ~500 chars of the offending body are attached as ``response_preview``
    to aid debugging.
    """

    def __init__(self, message: str = "failed to parse response", *, response_preview: str | None = None):
        super().__init__(message)
        self.response_preview = response_preview


_RETRY_AFTER_RE = re.compile(r"через\s+(\d+)\s*сек")
_STATUS_RE = re.compile(r"(?:Ошибка сервера:|HTTP)\s*(\d{3})")


def error_from_message(message: str | None, *, session_cookies: Mapping | None = None) -> MireaError:
    """
    Classify a failed result's message (and the session it ran with) as a typed error.

    The library reports failures as Russian text in ``result.message``; this maps that
    text to an exception class. The dead-session marker in ``session_cookies`` is the
    reliable signal for :class:`MireaSessionExpired`; the text is the fallback.
    Business refusals (a QR code for another lesson, marking not open yet) become a
    plain :class:`MireaError`.
    """
    text = (message or "").strip()
    low = text.lower()
    if pulse_session_needs_login(session_cookies) or "перелог" in low or ("сесси" in low and "истек" in low):
        return MireaSessionExpired(text or "session expired")
    retry = _RETRY_AFTER_RE.search(low)
    if retry:
        return MireaRateLimited(text, retry_after=float(retry.group(1)))
    status = _STATUS_RE.search(text)
    if status:
        code = int(status.group(1))
        if code == 429:
            return MireaRateLimited(text)
        if 500 <= code <= 599:
            return MireaServerError(text, status_code=code)
        return MireaError(text)
    if any(marker in low for marker in ("не отвечает", "таймаут", "ошибка сети", "временно недоступна")):
        return MireaServerError(text)
    if any(marker in low for marker in ("пустой ответ", "не удалось распарсить", "неизвестный ответ")):
        return MireaParseFailed(text)
    return MireaError(text or "MIREA request failed")


class RaisesForError:
    """Mixin for result dataclasses with ``success`` and ``message`` fields."""

    def raise_for_error(self, session_cookies: Mapping | None = None) -> None:
        """Do nothing on success; otherwise raise the matching :class:`MireaError` subclass."""
        if getattr(self, "success", False):
            return
        raise error_from_message(getattr(self, "message", None), session_cookies=session_cookies)


__all__ = [
    "error_from_message",
    "RaisesForError",
    "MireaError",
    "MireaSessionExpired",
    "MireaRefreshFailed",
    "MireaRateLimited",
    "MireaServerError",
    "MireaParseFailed",
]
