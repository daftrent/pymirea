"""pymirea — async-клиент для Пульса МИРЭА.

Покрывает: вход + 2FA (Keycloak SSO), расписание, оценки,
посещаемость, события турникетов (ACS), регистрацию в e-sports,
шифрование cookies (Fernet+HKDF).

Быстрый старт::

    from pymirea import Config, configure, MireaAuth

    configure(Config(session_keys="base64-32-байтная-строка"))

    auth = MireaAuth()
    result = await auth.login("s12345@edu.mirea.ru", "пароль")
    if result.challenge:
        # требуется 2FA — попросите у юзера OTP, потом:
        result = await auth.complete_2fa(result.challenge, "123456")

    # result.tokens — access/refresh/id-токены для последующего API.
"""

from ._settings import configure
from .acs import MireaACS
from .auth import AuthChallenge, AuthResult, MireaAuth
from .client import Client
from .config import Config
from .crypto import SessionCrypto
from .esports import MireaEsports
from .exceptions import (
    MireaError,
    MireaParseFailed,
    MireaRateLimited,
    MireaRefreshFailed,
    MireaServerError,
    MireaSessionExpired,
    error_from_message,
)
from .pulse_session import has_pulse_auth_cookie, pulse_session_needs_login
from .schedule import (
    ClassroomInfo,
    GroupInfo,
    MireaSchedule,
    Schedule,
    ScheduleEvent,
)
from .session import MireaAPI
from .tokens import (
    ensure_fresh_token,
    get_authorization_header,
    get_token_age_seconds,
    get_token_exp,
    try_refresh_tokens,
)

__all__ = [
    "Config",
    "configure",
    "Client",
    "MireaAPI",
    "MireaACS",
    "MireaAuth",
    "MireaEsports",
    "MireaSchedule",
    "Schedule",
    "ScheduleEvent",
    "GroupInfo",
    "ClassroomInfo",
    "SessionCrypto",
    "AuthChallenge",
    "AuthResult",
    "MireaError",
    "MireaSessionExpired",
    "MireaRefreshFailed",
    "MireaRateLimited",
    "MireaServerError",
    "MireaParseFailed",
    "error_from_message",
    "ensure_fresh_token",
    "has_pulse_auth_cookie",
    "pulse_session_needs_login",
    "get_authorization_header",
    "get_token_age_seconds",
    "get_token_exp",
    "try_refresh_tokens",
]

__version__ = "0.5.1"
