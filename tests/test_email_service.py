import os
import unittest
from unittest.mock import patch

from email_service import deliver_password_reset_code, email_mode


class EmailServiceTests(unittest.TestCase):
    def test_development_mode_returns_code_without_sending_email(self):
        with patch.dict(
            os.environ,
            {"APP_ENV": "development", "EMAIL_MODE": "development"},
            clear=True,
        ), patch("email_service.smtplib.SMTP") as smtp:
            self.assertEqual(
                deliver_password_reset_code("student@example.edu", "042817"),
                "042817",
            )
        smtp.assert_not_called()

    def test_development_mode_requires_explicit_development_environment(self):
        with patch.dict(os.environ, {"EMAIL_MODE": "development"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "APP_ENV=development"):
                email_mode()

    def test_development_mode_is_blocked_on_hosted_deployment(self):
        with patch.dict(
            os.environ,
            {
                "APP_ENV": "development",
                "EMAIL_MODE": "development",
                "RENDER": "true",
            },
            clear=True,
        ):
            with self.assertRaisesRegex(RuntimeError, "hosted deployments"):
                email_mode()

    def test_development_mode_is_blocked_when_app_environment_is_production(self):
        with patch.dict(
            os.environ,
            {"APP_ENV": "production", "EMAIL_MODE": "development"},
            clear=True,
        ):
            with self.assertRaisesRegex(RuntimeError, "APP_ENV=development"):
                email_mode()

    def test_production_mode_requires_configured_smtp(self):
        with patch.dict(
            os.environ,
            {"APP_ENV": "production", "EMAIL_MODE": "production"},
            clear=True,
        ):
            with self.assertRaisesRegex(RuntimeError, "SMTP_HOST"):
                deliver_password_reset_code("student@example.edu", "042817")

    @patch("email_service.smtplib.SMTP")
    def test_production_mode_sends_email_through_smtp(self, smtp):
        with patch.dict(
            os.environ,
            {
                "EMAIL_MODE": "production",
                "SMTP_HOST": "smtp.example.com",
                "SMTP_FROM_EMAIL": "noreply@example.com",
                "SMTP_USE_TLS": "false",
            },
            clear=True,
        ):
            self.assertIsNone(
                deliver_password_reset_code("student@example.edu", "042817")
            )
        smtp.assert_called_once_with("smtp.example.com", 587, timeout=15)
        smtp.return_value.__enter__.return_value.send_message.assert_called_once()

    def test_unknown_email_mode_is_rejected(self):
        with patch.dict(os.environ, {"EMAIL_MODE": "console"}, clear=True):
            with self.assertRaisesRegex(ValueError, "EMAIL_MODE"):
                email_mode()


if __name__ == "__main__":
    unittest.main()
