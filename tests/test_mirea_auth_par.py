"""Pulse owns PAR/code exchange; all credentials and HTTP responses are fixtures."""
import base64
import json
import secrets
import unittest
from dataclasses import asdict
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs

import httpx

from pymirea import Config, configure
from pymirea.auth import AuthChallenge, MireaAuth

configure(Config(session_keys=base64.b64encode(secrets.token_bytes(32)).decode()))

SSO = 'https://sso.mirea.ru/realms/mirea/login-actions/authenticate'
CALLBACK = 'https://pulse.mirea.ru/api/mireaauth?code=one-use&state=fixture'


def page(page_id='qr-login', **extra):
    return json.dumps({'pageId': page_id, 'loginAction': SSO, **extra})


def form_post(action='https://pulse.mirea.ru/api/mireaauth'):
    # Keycloak's response_mode=form_post page, as it is rendered by the server.
    return httpx.Response(200, text=(
        '<HTML><HEAD><TITLE>Submit This Form</TITLE></HEAD>'
        '<BODY Onload="javascript:document.forms[0].submit()">'
        f'<FORM METHOD="POST" ACTION="{action}">'
        '<INPUT TYPE="HIDDEN" NAME="code" VALUE="one-use"/>'
        '<INPUT TYPE="HIDDEN" NAME="state" VALUE="fixture"/>'
        '<INPUT TYPE="HIDDEN" NAME="iss" VALUE="https://sso.mirea.ru/realms/mirea"/>'
        '<NOSCRIPT><INPUT TYPE="SUBMIT" VALUE="CONTINUE"/></NOSCRIPT>'
        '</FORM></BODY></HTML>'))


class PulseLoginTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.requests = []
        self.clients = []
        self.password_response = httpx.Response(302, headers={'Location': CALLBACK})
        self.otp_response = httpx.Response(302, headers={'Location': CALLBACK})
        self.skip_response = httpx.Response(302, headers={'Location': CALLBACK})
        self.callback_cookie = 'Pulse.Auth.Cookie=session; Path=/; Secure; HttpOnly'
        self.breaker = AsyncMock()
        self.breaker.allow.return_value.allowed = True
        self.patch = patch('pymirea.auth.get_breaker', return_value=self.breaker)
        self.patch.start()

    async def asyncTearDown(self):
        self.patch.stop()
        for client in self.clients:
            await client.aclose()

    def auth(self):
        auth = MireaAuth.__new__(MireaAuth)
        auth.client = httpx.AsyncClient(transport=httpx.MockTransport(self.handle), follow_redirects=True)
        auth.proxy_client = None
        self.clients.append(auth.client)
        return auth

    def handle(self, request):
        self.requests.append(request)
        path = request.url.path
        if path == '/api/auth/login':
            self.assertEqual(request.url.params['redirectUri'], 'https://pulse.mirea.ru/')
            return httpx.Response(302, headers=[('Location', SSO),
                ('Set-Cookie', 'state=pulse-state; Path=/api; Secure')])
        if request.method == 'GET' and request.url.host == 'sso.mirea.ru':
            return httpx.Response(200, text=page(), headers=[
                ('Set-Cookie', 'state=sso-state; Path=/; Secure'),
                ('Set-Cookie', 'AUTH_SESSION_ID=sso-flow; Path=/realms/mirea/; Secure')])
        if request.method == 'POST' and request.url.host == 'sso.mirea.ru':
            self.assertNotIn('pulse-state', request.headers.get('cookie', ''))
            self.assertIn('AUTH_SESSION_ID=sso-flow', request.headers.get('cookie', ''))
            data = parse_qs(request.content.decode())
            if data.get('skip') == ['true']:
                return self.skip_response
            # The current email form submits login=true through its JS handler.
            # Without it SSO renders the same challenge, even for a correct code.
            if 'emailCode' in data and data.get('login') != ['true']:
                return httpx.Response(200, text=page('email-code-form'))
            return self.password_response if 'password' in data else self.otp_response
        if path == '/api/mireaauth':
            if request.method == 'POST':
                self.assertEqual(parse_qs(request.content.decode()), {
                    'code': ['one-use'], 'state': ['fixture'], 'iss': ['https://sso.mirea.ru/realms/mirea']})
            else:
                self.assertEqual(request.method, 'GET')
            self.assertIn('state=pulse-state', request.headers.get('cookie', ''))
            self.assertNotIn('sso-flow', request.headers.get('cookie', ''))
            headers = [('Location', 'https://pulse.mirea.ru/')]
            if self.callback_cookie:
                headers.append(('Set-Cookie', self.callback_cookie))
            return httpx.Response(302, headers=headers)
        if request.url.host == 'pulse.mirea.ru' and path == '/':
            return httpx.Response(200, text='<html>Pulse</html>')
        self.fail('Unexpected request: ' + request.url.path)

    async def test_password_login_lets_pulse_consume_code_once(self):
        result = await self.auth().login('fixture', 'test-password')
        self.assertTrue(result.success)
        self.assertEqual(result.cookies['Pulse.Auth.Cookie'], 'session')
        self.assertEqual(sum(r.url.path == '/api/mireaauth' for r in self.requests), 1)
        self.assertFalse(any('/protocol/openid-connect/' in r.url.path for r in self.requests))

    async def test_otp_roundtrip_preserves_scoped_cookies_and_challenge_kind(self):
        for kind, extras, field in [('email-code-form', {}, 'emailCode'),
                                    ('login-max-otp', {}, 'code'),
                                    ('login-otp', {'otpLogin': True}, 'otp')]:
            with self.subTest(kind=kind):
                self.password_response = httpx.Response(200, text=page(kind, **extras))
                first = await self.auth().login('fixture', 'test-password')
                self.assertFalse(first.success)
                self.assertEqual(first.challenge.field_name, field)
                # Exactly the encrypted challenge's JSON shape saved by mobile_auth.
                restored = AuthChallenge(**json.loads(json.dumps(asdict(first.challenge))))
                second = await self.auth().submit_otp(restored, '123456', cookies={})
                self.assertTrue(second.success)
                self.assertEqual(second.cookies['Pulse.Auth.Cookie'], 'session')

    async def test_form_post_callback_completes_login(self):
        # Observed since 26.10.2026: Pulse uses response_mode=form_post.
        cases = {
            'password only': (form_post(), None, None),
            'email code': (httpx.Response(200, text=page('email-code-form')), form_post(), None),
            'email code, MAX skipped': (httpx.Response(200, text=page('email-code-form')),
                httpx.Response(200, text=page('login-max-otp', phoneNotRegistered=True, showSkip=True)),
                form_post()),
        }
        for name, (password_response, otp_response, skip_response) in cases.items():
            with self.subTest(name):
                self.requests.clear()
                self.password_response, self.otp_response = password_response, otp_response
                self.skip_response = skip_response
                result = await self.auth().login('fixture', 'test-password')
                if result.challenge:
                    result = await self.auth().submit_otp(result.challenge, '123456')
                self.assertTrue(result.success, result.message)
                self.assertEqual(result.cookies['Pulse.Auth.Cookie'], 'session')
                callbacks = [r for r in self.requests if r.url.path == '/api/mireaauth']
                self.assertEqual([r.method for r in callbacks], ['POST'])

    async def test_form_post_code_is_never_sent_outside_pulse(self):
        for action in ('https://example.invalid/api/mireaauth', 'https://sso.mirea.ru/realms/mirea',
                       'http://pulse.mirea.ru/api/mireaauth'):
            with self.subTest(action=action):
                self.requests.clear()
                self.password_response = form_post(action)
                self.assertFalse((await self.auth().login('fixture', 'test-password')).success)
                self.assertFalse(any('one-use' in r.content.decode() for r in self.requests))

    async def test_rejected_otp_preserves_cookie_scope_for_retry(self):
        self.password_response = httpx.Response(200, text=page('email-code-form'))
        first = await self.auth().login('fixture', 'test-password')
        self.otp_response = httpx.Response(200, text=page('email-code-form'))
        retry = await self.auth().submit_otp(first.challenge, '000000')
        self.assertFalse(retry.success)
        self.assertIsNotNone(retry.challenge.pulse_cookies)
        self.otp_response = httpx.Response(302, headers={'Location': CALLBACK})
        self.assertTrue((await self.auth().submit_otp(retry.challenge, '123456')).success)

    async def test_pending_email_challenge_from_previous_release_is_repaired(self):
        self.password_response = httpx.Response(200, text=page('email-code-form'))
        first = await self.auth().login('fixture', 'test-password')
        first.challenge.hidden_fields = {}  # Previously stored encrypted challenge.
        self.assertTrue((await self.auth().submit_otp(first.challenge, '123456')).success)
        self.assertEqual(first.challenge.hidden_fields, {}, 'do not mutate stored input')

    async def test_wrong_password_and_missing_pulse_cookie_fail_closed(self):
        self.password_response = httpx.Response(200, text=page('qr-login'))
        result = await self.auth().login('fixture', 'bad-password')
        self.assertFalse(result.success)
        self.assertIsNone(result.challenge)
        self.password_response = httpx.Response(302, headers={'Location': CALLBACK})
        self.callback_cookie = None
        self.assertFalse((await self.auth().login('fixture', 'test-password')).success)

    async def test_post_is_not_replayed_on_307(self):
        self.password_response = httpx.Response(307, headers={'Location': CALLBACK})
        self.assertFalse((await self.auth().login('fixture', 'test-password')).success)
        self.assertFalse(any(r.url.path == '/api/mireaauth' for r in self.requests))

    async def test_external_redirect_is_not_followed(self):
        self.password_response = httpx.Response(302, headers={'Location': 'https://example.invalid/callback'})
        self.assertFalse((await self.auth().login('fixture', 'test-password')).success)
        self.assertFalse(any(r.url.host == 'example.invalid' for r in self.requests))

    async def test_malicious_form_never_receives_credentials(self):
        auth = self.auth()
        response = httpx.Response(200, text=json.dumps({'loginAction': 'https://evil.invalid/login'}),
                                  request=httpx.Request('GET', SSO))
        original = auth._pulse_request
        async def bootstrap(method, url, **kwargs):
            if method == 'GET':
                return response
            return await original(method, url, **kwargs)
        with patch.object(auth, '_pulse_request', side_effect=bootstrap):
            self.assertFalse((await auth.login('fixture', 'test-password')).success)
        self.assertEqual(self.requests, [])

    async def test_optional_max_enrollment_skip_keeps_pulse_callback(self):
        self.password_response = httpx.Response(200, text=page('max-account-config'))
        self.assertTrue((await self.auth().login('fixture', 'test-password')).success)
        self.assertEqual(parse_qs(self.requests[-3].content.decode()), {'skip': ['true']})

    async def test_accepted_email_code_skips_explicitly_optional_max_setup(self):
        self.password_response = httpx.Response(200, text=page('email-code-form'))
        first = await self.auth().login('fixture', 'test-password')
        # Observed after the owner's valid email OTP: this is enrollment, not another OTP.
        self.otp_response = httpx.Response(200, text=page('login-max-otp', isEnrollment=True, showSkip=True))
        result = await self.auth().submit_otp(first.challenge, '123456')
        self.assertTrue(result.success)
        self.assertIsNone(result.challenge)
        posts = [parse_qs(r.content.decode()) for r in self.requests if r.method == 'POST']
        self.assertEqual(posts[-2:], [{'login': ['true'], 'emailCode': ['123456']}, {'skip': ['true']}])
        self.assertEqual(sum(r.url.path == '/api/mireaauth' for r in self.requests), 1)

    async def test_real_max_otp_and_non_skippable_setup_are_not_skipped(self):
        for flags in ({'isEnrollment': False, 'showSkip': True},
                      {'isEnrollment': True, 'showSkip': False},
                      {'phoneNotRegistered': True, 'showSkip': False},
                      {'noPhoneNumber': True},
                      {'phoneNotRegistered': True, 'showSkip': True, 'deliveryPending': True},
                      {'noPhoneNumber': True, 'showSkip': True, 'sendFailed': True},
                      {'isEnrollment': True, 'showSkip': True, 'deliveryPending': True}, {}):
            with self.subTest(flags=flags):
                self.password_response = httpx.Response(200, text=page('login-max-otp', **flags))
                result = await self.auth().login('fixture', 'test-password')
                self.assertFalse(result.success)
                self.assertFalse(any(parse_qs(r.content.decode()).get('skip') for r in self.requests))

    async def test_email_then_optional_unavailable_max_without_enrollment(self):
        # SSO's MAX UI exposes Skip for these two states even with isEnrollment=false.
        for flags in ({'phoneNotRegistered': True}, {'noPhoneNumber': True}):
            with self.subTest(flags=flags):
                self.requests.clear()
                self.password_response = httpx.Response(200, text=page('email-code-form'))
                first = await self.auth().login('fixture', 'test-password')
                self.otp_response = httpx.Response(200, text=page('login-max-otp',
                    isEnrollment=False, showSkip=True, **flags))
                result = await self.auth().submit_otp(first.challenge, '123456')
                self.assertTrue(result.success)
                self.assertIsNone(result.challenge)
                posts = [parse_qs(r.content.decode()) for r in self.requests if r.method == 'POST']
                self.assertEqual(posts[-2:], [{'login': ['true'], 'emailCode': ['123456']}, {'skip': ['true']}])
                self.assertEqual(sum(r.url.path == '/api/mireaauth' for r in self.requests), 1)

    async def test_optional_phone_step_cannot_skip_following_real_max_otp(self):
        self.password_response = httpx.Response(200, text=page('login-max-otp',
            phoneNotRegistered=True, showSkip=True, isEnrollment=False))
        self.skip_response = httpx.Response(200, text=page('login-max-otp',
            phoneNotRegistered=False, showSkip=True, isEnrollment=False))
        result = await self.auth().login('fixture', 'test-password')
        self.assertFalse(result.success)
        self.assertEqual(result.challenge.field_name, 'code')
        self.assertEqual(sum(parse_qs(r.content.decode()).get('skip') == ['true'] for r in self.requests), 1)
        self.assertTrue((await self.auth().submit_otp(result.challenge, '654321')).success)
        posts = [parse_qs(r.content.decode()) for r in self.requests if r.method == 'POST']
        self.assertEqual(posts[-1], {'login': ['true'], 'code': ['654321']})

    async def test_max_setup_skip_cannot_loop_forever_or_reuse_email_code(self):
        self.password_response = httpx.Response(200, text=page('login-max-otp', isEnrollment=True, showSkip=True))
        self.skip_response = httpx.Response(200, text=page('login-max-otp', isEnrollment=True, showSkip=True))
        result = await self.auth().login('fixture', 'test-password')
        self.assertFalse(result.success)
        self.assertLessEqual(len(self.requests), 8)
        self.assertFalse(any('emailCode' in parse_qs(r.content.decode()) for r in self.requests))

    def test_cookie_serialization_keeps_duplicate_names_paths_and_expiry(self):
        auth = self.auth()
        for host, path, value in [('pulse.mirea.ru', '/api', 'correlation'),
                                  ('sso.mirea.ru', '/', 'sso'), ('sso.mirea.ru', '/realms/mirea', 'flow')]:
            auth.client.cookies.set('same-name', value, domain=host, path=path)
        for cookie in auth.client.cookies.jar:
            cookie.secure, cookie.expires = True, 2000000000
        state = auth._pulse_cookie_state()
        other = self.auth()
        other._restore_pulse_cookies(json.loads(json.dumps(state)))
        self.assertEqual(other._pulse_cookie_state(), state)
