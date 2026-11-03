"""
Сервис для получения событий СКУД (пропусков) из Pulse/Attendance через gRPC-Web.

Методы:
- UserService/GetMeInfo
- HumanPassService/GetHumanAcsEvents
"""

from __future__ import annotations

import base64
import logging
import re
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from datetime import time as dtime

import httpx

from ._http import make_async_client
from ._settings import settings
from .pulse_session import SESSION_EXPIRED_MESSAGE, is_pulse_auth_cookie
from .tokens import get_authorization_header
from .upstreams import get_breaker

logger = logging.getLogger(__name__)


_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_UUID_ANY_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)
_HEX_TOKEN_RE = re.compile(r"^[0-9a-f-]{24,}$", re.IGNORECASE)

_APP_URL = "https://pulse.mirea.ru"
_GET_ME_URL = "https://pulse.mirea.ru/rtu_tc.rtu_attend.app.UserService/GetMeInfo"
_GET_ACS_EVENTS_URL = (
    "https://pulse.mirea.ru/"
    "rtu_tc.rtu_attend.humanpass.HumanPassService/GetHumanAcsEvents"
)

_MSK_TZ = timezone(timedelta(hours=3))


@dataclass
class AcsEvent:
    ts: int
    time_label: str
    enter_zone: str
    exit_zone: str
    duration_seconds: int | None
    duration_label: str | None


@dataclass
class AcsResult:
    success: bool
    message: str
    events: list[AcsEvent]
    date: str | None = None


class MireaACS:
    _HUMAN_ID_CACHE_KEY = "__acs_human_id"

    def __init__(self, session_cookies: dict):
        self.session_cookies = session_cookies or {}
        cookies = httpx.Cookies()
        for name, value in (self.session_cookies or {}).items():
            if not value:
                continue
            if str(name).startswith("__"):
                continue
            if name in {"access_token", "token_type", "refresh_token", "expires_in"}:
                continue
            cookies.set(str(name), str(value), domain=".mirea.ru")

        limits = httpx.Limits(max_connections=100, max_keepalive_connections=50, keepalive_expiry=10.0)
        timeout = httpx.Timeout(25.0, connect=10.0)
        self.client = make_async_client(
            follow_redirects=True,
            timeout=timeout,
            cookies=cookies,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6_2 like Mac OS X) "
                    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1"
                ),
                "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
            },
            transport=httpx.AsyncHTTPTransport(retries=2, limits=limits),
            proxy=settings.mirea_proxy if settings.mirea_proxy else None,
        )

    async def close(self):
        await self.client.aclose()

    async def _recover_session(self) -> bool:
        """Renew the Pulse session (shared with MireaGrades) and load the new cookie into this client."""
        from .grades import renew_pulse_session

        if not await renew_pulse_session(self.session_cookies):
            return False
        jar = self.client.cookies.jar
        for cookie in [c for c in jar if is_pulse_auth_cookie(c.name or "")]:
            try:
                jar.clear(cookie.domain, cookie.path, cookie.name)
            except KeyError:
                pass
        for name, value in self.session_cookies.items():
            if value and is_pulse_auth_cookie(str(name)):
                self.client.cookies.set(str(name), str(value), domain=".mirea.ru")
        return True

    def _grpc_headers(self) -> dict:
        headers = {
            "Content-Type": "application/grpc-web+proto",
            "x-grpc-web": "1",
            "x-requested-with": "XMLHttpRequest",
            "Origin": _APP_URL,
            "Referer": f"{_APP_URL}/",
            "pulse-app-type": "pulse-app",
            "pulse-app-version": "1.6.0+5227",
            "Accept": "*/*",
        }
        authz = get_authorization_header(self.session_cookies)
        if authz:
            headers["Authorization"] = authz
        return headers

    @staticmethod
    def _grpc_web_frame(payload: bytes) -> bytes:
        return struct.pack(">BI", 0, len(payload)) + payload

    @staticmethod
    def _parse_grpc_web_frames(data: bytes) -> tuple[list[bytes], dict[str, str]]:
        msgs: list[bytes] = []
        trailers: dict[str, str] = {}
        pos = 0
        while pos + 5 <= len(data):
            flag = data[pos]
            length = struct.unpack(">I", data[pos + 1 : pos + 5])[0]
            pos += 5
            if pos + length > len(data):
                break
            payload = data[pos : pos + length]
            pos += length

            if flag == 0x00:
                msgs.append(payload)
                continue
            if flag == 0x80:
                try:
                    text = payload.decode("utf-8", errors="ignore")
                    for line in text.split("\r\n"):
                        if not line or ":" not in line:
                            continue
                        k, v = line.split(":", 1)
                        trailers[k.strip().lower()] = v.strip()
                except Exception:
                    pass
        return msgs, trailers

    @staticmethod
    def _try_decode_grpc_web_text(data: bytes) -> bytes | None:
        """
        grpc-web-text приходит base64-строкой вместо бинарных фреймов.
        Пробуем мягко декодировать, если вход похож на base64.
        """
        if not data:
            return None
        text = data.strip()
        if not text:
            return None
        if not re.fullmatch(rb"[A-Za-z0-9+/=\r\n]+", text):
            return None
        compact = re.sub(rb"[\r\n\s]+", b"", text)
        if not compact or (len(compact) % 4) != 0:
            return None
        try:
            return base64.b64decode(compact, validate=False)
        except Exception:
            return None

    async def _grpc_unary(
        self,
        url: str,
        proto_payload: bytes,
        *,
        allow_empty_message: bool = False,
        refresh_retry: bool = True,
    ) -> tuple[bytes | None, str | None]:
        breaker = get_breaker("mirea_acs_grpc")
        decision = await breaker.allow()
        if not decision.allowed:
            retry_after = decision.retry_after_s or 5
            return None, f"МИРЭА временно недоступна. Попробуйте через {retry_after} сек."

        try:
            resp = await self.client.post(
                url,
                content=self._grpc_web_frame(proto_payload),
                headers=self._grpc_headers(),
            )
        except httpx.TimeoutException:
            logger.warning("grpc timeout url=%s", url)
            await breaker.record_failure()
            return None, "Таймаут запроса к МИРЭА"
        except Exception as e:
            logger.warning("grpc network error url=%s: %s", url, e)
            await breaker.record_failure()
            return None, f"Ошибка сети: {e}"

        if resp.status_code != 200:
            if 500 <= int(resp.status_code) <= 599:
                await breaker.record_failure()
            else:
                await breaker.record_success()
            if resp.status_code == 401:
                # Pulse answers a missing or rejected auth cookie with a bare 401. Renew the
                # session once and repeat; the first request was rejected, nothing is done twice.
                if refresh_retry and await self._recover_session():
                    return await self._grpc_unary(
                        url,
                        proto_payload,
                        allow_empty_message=allow_empty_message,
                        refresh_retry=False,
                    )
                return None, SESSION_EXPIRED_MESSAGE
            return None, f"HTTP {resp.status_code}"

        raw_content = resp.content or b""
        msgs, trailers = self._parse_grpc_web_frames(raw_content)
        if not msgs and not trailers:
            decoded = self._try_decode_grpc_web_text(raw_content)
            if decoded:
                msgs, trailers = self._parse_grpc_web_frames(decoded)
        grpc_status = trailers.get("grpc-status")
        if grpc_status and grpc_status != "0":
            grpc_message = trailers.get("grpc-message") or "gRPC error"
            if refresh_retry and grpc_status in {"7", "16"}:
                if await self._recover_session():
                    return await self._grpc_unary(
                        url,
                        proto_payload,
                        allow_empty_message=allow_empty_message,
                        refresh_retry=False,
                    )
            await breaker.record_success()
            return None, grpc_message
        if not msgs:
            preview = (raw_content[:300] or b"").decode("utf-8", errors="ignore").lower()
            looks_like_auth = ("<html" in preview or "keycloak" in preview or "login" in preview or "signin" in preview)
            if looks_like_auth and refresh_retry:
                if await self._recover_session():
                    return await self._grpc_unary(
                        url,
                        proto_payload,
                        allow_empty_message=allow_empty_message,
                        refresh_retry=False,
                    )
            if looks_like_auth:
                await breaker.record_success()
                return None, SESSION_EXPIRED_MESSAGE
            if allow_empty_message:
                await breaker.record_success()
                return b"", None
            await breaker.record_success()
            return None, "Пустой ответ gRPC"
        await breaker.record_success()
        return msgs[0], None

    @staticmethod
    def _encode_varint(value: int) -> bytes:
        out = bytearray()
        v = int(value)
        while v > 0x7F:
            out.append((v & 0x7F) | 0x80)
            v >>= 7
        out.append(v & 0x7F)
        return bytes(out)

    @staticmethod
    def _decode_varint(data: bytes, pos: int) -> tuple[int, int]:
        result = 0
        shift = 0
        while pos < len(data):
            b = data[pos]
            pos += 1
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                return result, pos
            shift += 7
            if shift > 70:
                break
        return result, pos

    def _skip_field(self, data: bytes, pos: int, wire_type: int) -> int:
        if wire_type == 0:
            _, pos = self._decode_varint(data, pos)
            return pos
        if wire_type == 1:
            return pos + 8
        if wire_type == 5:
            return pos + 4
        if wire_type == 2:
            length, pos = self._decode_varint(data, pos)
            return pos + int(length)
        return pos

    def _read_length_delimited(self, data: bytes, pos: int) -> tuple[bytes, int]:
        length, pos = self._decode_varint(data, pos)
        length_i = int(length)
        if pos + length_i > len(data):
            return b"", len(data)
        value = data[pos : pos + length_i]
        return value, pos + length_i

    def _field_varint(self, field_no: int, value: int) -> bytes:
        key = (int(field_no) << 3) | 0
        return self._encode_varint(key) + self._encode_varint(int(value))

    def _field_bytes(self, field_no: int, value: bytes) -> bytes:
        key = (int(field_no) << 3) | 2
        return self._encode_varint(key) + self._encode_varint(len(value)) + value

    def _field_string(self, field_no: int, value: str) -> bytes:
        return self._field_bytes(field_no, (value or "").encode("utf-8"))

    def _encode_get_me_request(self) -> bytes:
        origin = _APP_URL
        nested = self._field_string(1, origin)
        return b"".join(
            [
                self._field_string(1, origin),
                self._field_bytes(2, nested),
                self._field_varint(3, 1),
            ]
        )

    def _encode_timestamp(self, dt_utc: datetime) -> bytes:
        sec = int(dt_utc.timestamp())
        nanos = max(0, int(dt_utc.microsecond) * 1000)
        out = bytearray()
        out.extend(self._field_varint(1, sec))
        if nanos:
            out.extend(self._field_varint(2, nanos))
        return bytes(out)

    def _encode_time_range(self, start_utc: datetime, end_utc: datetime) -> bytes:
        return b"".join(
            [
                self._field_bytes(1, self._encode_timestamp(start_utc)),
                self._field_bytes(2, self._encode_timestamp(end_utc)),
            ]
        )

    def _encode_get_acs_events_request(self, human_id: str, start_utc: datetime, end_utc: datetime) -> bytes:
        return b"".join(
            [
                self._field_string(1, human_id),
                self._field_bytes(2, self._encode_time_range(start_utc, end_utc)),
                self._field_varint(3, 1),  # all events
                self._field_varint(5, 2),  # desc order
            ]
        )

    def _extract_uuid_strings(self, data: bytes, *, max_depth: int = 8) -> list[str]:
        found: list[str] = []

        def _walk(buf: bytes, depth: int) -> None:
            if depth > max_depth:
                return
            p = 0
            while p < len(buf):
                key, p = self._decode_varint(buf, p)
                wt = key & 0x7
                if wt == 2:
                    raw, p = self._read_length_delimited(buf, p)
                    try:
                        s = raw.decode("utf-8").strip()
                        if _UUID_RE.match(s):
                            found.append(s)
                    except Exception:
                        pass
                    _walk(raw, depth + 1)
                    continue
                p = self._skip_field(buf, p, wt)

        _walk(data, 0)
        out: list[str] = []
        seen: set[str] = set()
        for item in found:
            if item in seen:
                continue
            seen.add(item)
            out.append(item)
        return out

    def _parse_timestamp_message(self, data: bytes) -> float | None:
        sec: int | None = None
        nanos = 0
        p = 0
        while p < len(data):
            key, p = self._decode_varint(data, p)
            field = key >> 3
            wt = key & 0x7
            if wt == 0 and field == 1:
                value, p = self._decode_varint(data, p)
                sec = int(value)
                continue
            if wt == 0 and field == 2:
                value, p = self._decode_varint(data, p)
                nanos = int(value)
                continue
            p = self._skip_field(data, p, wt)
        if sec is None:
            return None
        if sec < 1_500_000_000 or sec > 2_300_000_000:
            return None
        return float(sec) + float(nanos) / 1_000_000_000.0

    @staticmethod
    def _is_technical_token(text: str) -> bool:
        value = (text or "").strip()
        if not value:
            return True
        normalized = re.sub(r"^[^0-9A-Za-zА-Яа-я]+", "", value).strip()
        if not normalized:
            return True
        # Any embedded UUID means it's a service token, not a zone.
        if _UUID_ANY_RE.search(normalized):
            return True
        if _UUID_RE.match(normalized):
            return True
        if _HEX_TOKEN_RE.match(normalized):
            return True
        # Long single-token IDs without spaces/punctuation are not user-friendly zones.
        if " " not in normalized and re.fullmatch(r"[0-9A-Za-z_-]{28,}", normalized):
            return True
        return False

    @staticmethod
    def _looks_text(raw: bytes) -> str | None:
        try:
            text = raw.decode("utf-8").strip()
        except Exception:
            return None
        text = re.sub(r"\s+", " ", text)
        if not text or len(text) > 140:
            return None
        if text.startswith("http://") or text.startswith("https://"):
            return None
        printable = sum(1 for c in text if c.isprintable())
        if printable / max(len(text), 1) < 0.92:
            return None
        if MireaACS._is_technical_token(text):
            return None
        if not any(ch.isalpha() for ch in text):
            return None
        return text

    @staticmethod
    def _zone_score(text: str) -> int:
        value = (text or "").strip()
        if not value:
            return -100
        if MireaACS._is_technical_token(value):
            return -100
        score = 0
        lower = value.lower()
        for kw in ("кпп", "вход", "террит", "корпус", "проход", "зона"):
            if kw in lower:
                score += 5
        if re.search(r"[А-ЯA-Z]\d{1,3}", value):
            score += 3
        if 4 <= len(value) <= 64:
            score += 1
        return score

    def _parse_event_message(self, data: bytes, start_ts: float, end_ts: float) -> dict | None:
        strings: list[str] = []
        timestamps: list[float] = []

        def _walk(buf: bytes, depth: int) -> None:
            if depth > 6:
                return
            p = 0
            while p < len(buf):
                key, p = self._decode_varint(buf, p)
                wt = key & 0x7
                if wt == 0:
                    value, p = self._decode_varint(buf, p)
                    iv = int(value)
                    if 1_500_000_000 <= iv <= 2_300_000_000:
                        timestamps.append(float(iv))
                    continue
                if wt == 2:
                    raw, p = self._read_length_delimited(buf, p)
                    ts = self._parse_timestamp_message(raw)
                    if ts is not None:
                        timestamps.append(ts)
                    txt = self._looks_text(raw)
                    if txt:
                        strings.append(txt)
                    _walk(raw, depth + 1)
                    continue
                p = self._skip_field(buf, p, wt)

        _walk(data, 0)
        if not timestamps:
            return None

        windowed = [ts for ts in timestamps if (start_ts - 86400.0) <= ts <= (end_ts + 86400.0)]
        if not windowed:
            return None
        ts = int(max(windowed))

        uniq_strings: list[str] = []
        seen: set[str] = set()
        for s in strings:
            if s in seen:
                continue
            seen.add(s)
            uniq_strings.append(s)

        if not uniq_strings:
            return None

        zone_candidates = sorted(uniq_strings, key=self._zone_score, reverse=True)
        zone_candidates = [z for z in zone_candidates if self._zone_score(z) >= 2]
        readable = [z for z in uniq_strings if not self._is_technical_token(z)]
        if len(zone_candidates) >= 2:
            enter_zone = zone_candidates[0]
            exit_zone = zone_candidates[1]
        elif len(zone_candidates) == 1:
            enter_zone = zone_candidates[0]
            exit_zone = "Неизвестная зона"
        elif len(readable) >= 2:
            enter_zone = readable[0]
            exit_zone = readable[1]
        elif len(readable) == 1:
            enter_zone = readable[0]
            exit_zone = "Неизвестная зона"
        else:
            enter_zone = "Неизвестная зона"
            exit_zone = "Неизвестная зона"

        return {"ts": ts, "enter_zone": enter_zone, "exit_zone": exit_zone}

    def _extract_events_from_payload(self, payload: bytes, start_ts: float, end_ts: float) -> list[dict]:
        events: list[dict] = []

        def _walk(buf: bytes, depth: int) -> None:
            if depth > 6:
                return
            p = 0
            while p < len(buf):
                key, p = self._decode_varint(buf, p)
                wt = key & 0x7
                if wt == 2:
                    raw, p = self._read_length_delimited(buf, p)
                    event = self._parse_event_message(raw, start_ts, end_ts)
                    if event is not None:
                        events.append(event)
                    _walk(raw, depth + 1)
                    continue
                p = self._skip_field(buf, p, wt)

        _walk(payload, 0)

        dedup: list[dict] = []
        seen: set[tuple[int, str, str]] = set()
        for event in events:
            key = (int(event["ts"]), event["enter_zone"], event["exit_zone"])
            if key in seen:
                continue
            seen.add(key)
            dedup.append(event)
        dedup.sort(key=lambda x: int(x["ts"]), reverse=True)
        return dedup

    @staticmethod
    def _format_duration(seconds: int | None) -> str | None:
        if seconds is None or seconds <= 0:
            return None
        if seconds < 60:
            return "меньше минуты"
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        if hours and minutes:
            return f"{hours} ч {minutes} мин"
        if hours:
            return f"{hours} ч"
        return f"{minutes} мин"

    async def _resolve_human_ids(self) -> tuple[list[str], str | None]:
        cached = (self.session_cookies.get(self._HUMAN_ID_CACHE_KEY) or "").strip()
        candidates: list[str] = []
        if cached and _UUID_RE.match(cached):
            candidates.append(cached)

        payload, err = await self._grpc_unary(_GET_ME_URL, self._encode_get_me_request())
        if err or not payload:
            return candidates, err or "Не удалось получить профиль пользователя"

        for uid in self._extract_uuid_strings(payload):
            if uid not in candidates:
                candidates.append(uid)
        if not candidates:
            return [], "Не найден human_id в ответе МИРЭА"
        return candidates, None

    async def get_today_events(self) -> AcsResult:
        now_msk = datetime.now(_MSK_TZ)
        start_msk = datetime.combine(now_msk.date(), dtime.min, tzinfo=_MSK_TZ)
        end_msk = start_msk + timedelta(days=1) - timedelta(milliseconds=1)

        start_utc = start_msk.astimezone(timezone.utc)
        end_utc = end_msk.astimezone(timezone.utc)
        start_ts = start_utc.timestamp()
        end_ts = end_utc.timestamp()

        human_ids, err = await self._resolve_human_ids()
        if err and not human_ids:
            return AcsResult(success=False, message=err, events=[], date=start_msk.date().isoformat())

        last_error: str | None = None
        parsed_events: list[dict] = []
        used_human_id: str | None = None

        for human_id in human_ids[:8]:
            req = self._encode_get_acs_events_request(human_id, start_utc, end_utc)
            payload, call_err = await self._grpc_unary(
                _GET_ACS_EVENTS_URL,
                req,
                allow_empty_message=True,
            )
            if call_err:
                last_error = call_err or "Пустой ответ ACS"
                continue

            events = self._extract_events_from_payload(payload or b"", start_ts, end_ts)
            parsed_events = events
            used_human_id = human_id
            # Берем первый валидный ответ; пустой список тоже валидный кейс.
            break

        if used_human_id:
            self.session_cookies[self._HUMAN_ID_CACHE_KEY] = used_human_id

        if used_human_id is None:
            return AcsResult(
                success=False,
                message=last_error or "Не удалось получить события пропуска",
                events=[],
                date=start_msk.date().isoformat(),
            )

        events_out: list[AcsEvent] = []
        for idx, item in enumerate(parsed_events[:40]):
            ts = int(item["ts"])
            dt_msk = datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(_MSK_TZ)
            duration_seconds: int | None = None
            if idx + 1 < len(parsed_events):
                next_ts = int(parsed_events[idx + 1]["ts"])
                diff = ts - next_ts
                if 0 < diff <= 24 * 3600:
                    duration_seconds = diff
            events_out.append(
                AcsEvent(
                    ts=ts,
                    time_label=dt_msk.strftime("%H:%M"),
                    enter_zone=item.get("enter_zone") or "—",
                    exit_zone=item.get("exit_zone") or "—",
                    duration_seconds=duration_seconds,
                    duration_label=self._format_duration(duration_seconds),
                )
            )

        return AcsResult(
            success=True,
            message="ok",
            events=events_out,
            date=start_msk.date().isoformat(),
        )

    async def check_connection(self) -> tuple[bool, str]:
        """
        Lightweight connectivity/session check for profile diagnostics.
        """
        human_ids, err = await self._resolve_human_ids()
        if err and not human_ids:
            return False, err
        return True, "Соединение с МИРЭА активно"
