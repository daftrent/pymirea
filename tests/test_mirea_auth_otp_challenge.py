import base64
import secrets
import unittest

from pymirea import Config, configure
from pymirea.auth import MireaAuth  # noqa: E402

configure(Config(session_keys=base64.b64encode(secrets.token_bytes(32)).decode()))


class TestOtpChallengeExtraction(unittest.TestCase):
    def test_email_page_wins_over_other_authenticator_metadata(self):
        html = '''{"pageId":"email-code-form","loginAction":"https://sso.mirea.ru/login-actions/authenticate",
            "authenticationSelections":[{"displayName":"login-max-otp"}],"otpLogin":false}'''
        auth = MireaAuth.__new__(MireaAuth)
        challenge = auth._extract_otp_challenge(html)
        self.assertEqual(challenge.kind, 'email_code')
        self.assertEqual(challenge.field_name, 'emailCode')
        self.assertEqual(challenge.hidden_fields, {'login': 'true'})

    def test_max_page_wins_over_totp_metadata(self):
        html = '''{"pageId":"login-max-otp.ftl","loginAction":"https://sso.mirea.ru/login-actions/authenticate",
            "otpLogin":false,"otherTemplate":"email-code-form"}'''
        challenge = MireaAuth.__new__(MireaAuth)._extract_otp_challenge(html)
        self.assertEqual(challenge.field_name, 'code')

    def test_non_otp_page_is_not_a_challenge_despite_authenticator_metadata(self):
        html = '''{"pageId":"qr-login","loginAction":"https://sso.mirea.ru/login-actions/authenticate",
            "authenticationSelections":["login-max-otp","email-code-form"],"otpLogin":false}'''
        self.assertIsNone(MireaAuth.__new__(MireaAuth)._extract_otp_challenge(html))

    def test_spa_otp_login_action(self):
        html = '{"otpLogin":true,"loginAction":"https://sso.mirea.ru/auth/realms/x/login-actions/authenticate"}'
        auth = MireaAuth.__new__(MireaAuth)  # avoid creating http clients
        challenge = auth._extract_otp_challenge(html, base_url="https://sso.mirea.ru/")
        self.assertIsNotNone(challenge)
        self.assertEqual(challenge.kind, "otp")
        self.assertEqual(challenge.field_name, "otp")
        self.assertIn("https://sso.mirea.ru/", challenge.action_url)

    def test_classic_form_with_hidden_fields(self):
        html = """
        <html>
          <body>
            <form id="kc-otp-login-form" action="/login-actions/authenticate">
              <input type="hidden" name="session_code" value="abc">
              <input type="hidden" name="execution" value="def">
              <input type="text" name="otp" autocomplete="one-time-code">
            </form>
          </body>
        </html>
        """
        auth = MireaAuth.__new__(MireaAuth)
        challenge = auth._extract_otp_challenge(html, base_url="https://sso.mirea.ru/realms/x/")
        self.assertIsNotNone(challenge)
        self.assertEqual(challenge.kind, "otp")
        self.assertEqual(challenge.field_name, "otp")
        self.assertTrue(challenge.action_url.startswith("https://sso.mirea.ru/"))
        self.assertEqual(challenge.hidden_fields.get("session_code"), "abc")
        self.assertEqual(challenge.hidden_fields.get("execution"), "def")

    def test_heuristic_one_time_code_form(self):
        html = """
        <html>
          <body>
            <form action="https://sso.mirea.ru/login-actions/authenticate">
              <input type="hidden" name="foo" value="bar">
              <input type="tel" name="code" autocomplete="one-time-code" inputmode="numeric">
            </form>
          </body>
        </html>
        """
        auth = MireaAuth.__new__(MireaAuth)
        challenge = auth._extract_otp_challenge(html, base_url="https://sso.mirea.ru/")
        self.assertIsNotNone(challenge)
        self.assertEqual(challenge.kind, "otp")
        self.assertEqual(challenge.field_name, "code")
        self.assertEqual(challenge.hidden_fields.get("foo"), "bar")


if __name__ == "__main__":
    unittest.main()
