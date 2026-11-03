# для работы с Claude Code

## Контекст которого нет в коде

**Это reverse-engineered клиент закрытого API.** Никаких `.proto` файлов нет, схемы протобуфа никто не публиковал. Всё что в коде — результат раскрутки трафика реального фронта `pulse.mirea.ru`. Если МИРЭА что-то меняют — мы узнаём по падению успешности у пользователей, не из release notes.

**1 апреля 2026 МИРЭА сделали ломающие изменения:** переименовали gRPC методы на `rtu_tc.attendance.api.*` (раньше было что-то на `session.SessionService`), добавили required-action `max-account-config` после OTP, token exchange стал confidential client (нужен бутстрап `.AspNetCore.Cookies` через pulse). **6 октября 2026 снова:** cookie сессии переименована в `Pulse.Auth.Cookie`, `/api/baseinfo` удалён, метод отчёта БРС удалён, HTML `/selfapprove` отдаёт только оболочку SPA, вход идёт через PAR на стороне Пульса (с 08.10). Всё это перенесено в 0.5.0 из продакшена Pairx (`qrscaner`), подробности в CHANGELOG. Если код в дальнейшем сломается похожим образом — это не баг pymirea, это они снова что-то накатили; смотри начала с auth flow и gRPC путей.

## Auth flow подводные камни

Каждый из этих пунктов уже укусил, не повторяй ошибку:

**1. Cookies Keycloak на пути `/realms/mirea/`, не `/`.** Если делаешь `client.cookies` или `jar.Cookies(url)` с url = `https://sso.mirea.ru/` — получишь пустоту. Cookies AUTH_SESSION_ID, KC_RESTART, KC_AUTH_SESSION_HASH ставятся на path `/realms/mirea/login-actions/`. URL для пробинга должен включать этот путь.

**2. После успешного OTP МИРЭА показывает `max-account-config` required-action.** Эту страницу **обязательно надо скипнуть**, иначе не получишь auth code. Скип — POST на `loginAction` с `skip=true` (МИРЭА-тема Keycloak) или `cancel-aia=true` (стандартный Keycloak). **Клиент должен быть с отключенным follow_redirects** — иначе мы пропустим 302 с `?code=...` и потеряем код.

**3. Required-action HTML содержит `"login-max-otp"` в kcContext** (это название frontend-шаблона, не настоящий OTP-челлендж). `_extract_otp_challenge` будет его ошибочно матчить как новый 2FA. **Сначала проверяй URL на `required-action`, потом на OTP.**

**4. Без cookie Пульса все gRPC вызовы возвращают 401.** С 06.10.2026 это `Pulse.Auth.Cookie` (раньше `.AspNetCore.Cookies`, имена и параметры — `pulse_session.py`). Её выдаёт `pulse.mirea.ru/api/auth/login?redirectUri=https://pulse.mirea.ru/&rememberMe=True` при живой Keycloak-сессии. Bootstrap принимает любую cookie, выданную самим `pulse.mirea.ru`, и выкидывает старую копию с `.mirea.ru`, иначе уйдут обе одноимённые.

**4a. Не отправляй в SSO cookies потока входа** (`AUTH_SESSION_ID`, `KC_*`): после завершённого входа они устаревают, и Keycloak гоняет запрос по кругу до `TooManyRedirects`. Сессию определяют `KEYCLOAK_IDENTITY`/`KEYCLOAK_SESSION`.

**4c. Восстановление сессии одно на всех:** `pymirea.grades.renew_pulse_session(cookies)` (bootstrap через Keycloak-сессию, затем refresh токена). Им пользуются `MireaGrades`, `MireaAPI` (через grades) и `MireaACS`. Новый клиент Pulse должен вызывать его на 401 / gRPC 7, 16 / HTML-логине, а не только `try_refresh_tokens`. `MireaEsports` сюда не относится: у киберзоны свой вход через `login.mirea.ru` и JWT.

**4b. Keycloak-сессия без «запомнить меня» живёт 16 часов**, с `rememberMe=on` — около полугода. Мёртвую сессию bootstrap помечает `__pulse_bootstrap_failed_at`; приложение по `pulse_session_needs_login()` должно просить новый вход, а не повторять ошибку.

**5. Token exchange может вернуть 400 даже когда логин успешен** (confidential client). Падение exchange ≠ падение логина. Если есть KC cookies, можно работать через `.AspNetCore.Cookies` без access_token.

## Protobuf parsing — все парсеры эвристические

Никаких `.proto` нет. Все `_parse_*` функции — это разбор байт по варинтам и field numbers, угаданным из реверса. Это значит:

- **Парсеры не кидают исключения на невалидных данных** — возвращают пустые/частичные результаты. Это сделано намеренно: если МИРЭА меняют wire format, лучше получить пустой `Subject` чем краш.
- В 0.2.1 добавлены bounds checks в `_parse_grpc_web_frames` и `_read_length_delimited`. Если делаешь похожий новый парсер — **обязательно проверяй** `if pos + length > len(data)` перед slice.
- Wire format совместим с go-mirea (отдельная либа). Есть cross-library тест шифрования сессии. **Не меняй Fernet/HKDF в `crypto.py` без согласования** — оба порта рассчитывают на бинарную совместимость.

## Сессии и SESSION_KEYS

`SESSION_KEYS` это comma-separated Fernet-ключи. Первый = шифровка, все = расшифровка (key rotation). Если ротируешь — старый ключ оставляй пока юзеры с ним не пере-логинятся.

Самая частая ошибка в проде у пользователей библиотеки — `"Сессия истекла"`. Это не баг кода, это юзеры с протухшими cookies. Auto-refresh теоретически решает, но сложный релиз: race conditions при N одновременных вызовах надо разруливать через distributed lock.

## Стиль работы с этим репо

**Прод-стейкс высокий.** Эта библиотека работает в нескольких сервисах с тысячами активных юзеров. Поэтому:

- Только консервативные фиксы напрямую (как bounds checks в 0.2.1 — где нет шансов сломать)
- Эксперименты — отдельные релизы с feature flag, не подмена текущего поведения
- Любая фича типа auto-refresh токенов или TLS-spoofing — major релиз с opt-in флагом
- Принцип "70-80% стабильности лучше чем непонятно что" — поломать рабочее ради потенциального улучшения **не в стиле этого проекта**

## Тесты и линтер

```bash
pip install -e ".[dev]"  # ставит respx, pytest-asyncio
python3 -m pytest tests/ -q
python3 -m ruff check .  # CI ругается на F401 unused imports — прогоняй перед коммитом
```

247 тестов, HTTP мокается через respx или `httpx.MockTransport` (подмена `make_async_client`). Каждое сообщение об ошибке, которое отдаёт библиотека, должно быть в `tests/test_result_errors.py`: от него зависит `raise_for_error()`. Реальная МИРЭА в CI **не дёргается** — только моки. Любое тестирование против настоящего МИРЭА надо делать вручную с осторожностью (риск flag/ban аккаунта).

## Релиз

Теги v0.3.4–v0.4.0 не ставились, поэтому на PyPI до 0.5.0 была 0.3.3. Проверяй после релиза, что версия появилась на PyPI.

1. Бамп версии в `pyproject.toml`
2. Коммит на `main` (солопроект, PR не обязателен)
3. `git tag v0.x.y && git push --tags` — CI публикует на PyPI через OIDC trusted publishing
4. Через ~1 минуту `pip install pymirea==0.x.y` работает

## Чего НЕ делать

- Не убирай fallback'и (легаси sha256-derive ключа, KC bootstrap, второй вариант skip-payload, etc) — каждый был добавлен потому что юзер на это попадал
- Не пиши логи с содержимым `payload.hex()` на уровне INFO — DEBUG достаточно (фикснули в 0.2.1, не верни обратно)
- Не "оптимизируй" эвристические парсеры в сторону "более красивого кода" — каждая `if cat or name`, `try/except Exception: pass` там потому что МИРЭА может вернуть что угодно
- Не меняй сигнатуры публичных классов (`MireaAPI`, `MireaAuth`, `MireaGrades`, `MireaACS`, `MireaEsports`) без bump major — снаружи на них завязан внешний код
- Не предлагай TLS spoofing как срочный — пока успешность сканов в районе 80%, это резерв на случай ужесточения анти-бот защиты у МИРЭА. Реализация через `curl_cffi` как opt-in.

## Что хорошо бы знать про реальное использование

- Один и тот же объект `MireaAPI` (или `MireaGrades`, etc) надо `await api.close()` — клиент httpx держит коннекшны
- Cookies возвращаются как `dict[str, str]` (плоско, без атрибутов). Шифрование/расшифровка через `SessionCrypto` — внешний код хранит зашифрованный blob в БД
- `MireaAuth.refresh_tokens` принимает `refresh_token` строкой, не dict. Возвращает новые токены или None.
- `extract_token_from_qr` поддерживает 4 домена (`pulse.mirea.ru`, `attendance-app.mirea.ru`, `attendance.mirea.ru`, `att.mirea.ru`) — все актуальны, рандомно встречаются в QR
- `MireaACS.get_events_for_day` требует `humanID` который надо отдельно достать через `UserService.GetMeInfo` (этого автоматического резолва пока нет — TODO)
