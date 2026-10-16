import json
import os
import unittest
from unittest.mock import MagicMock, patch

from email_delivery import password_reset_email_configured, send_password_reset_email


class EmailDeliveryTests(unittest.TestCase):
    def test_resend_configuration_enables_password_recovery(self):
        with patch.dict(
            os.environ,
            {"RESEND_API_KEY": "test-key", "RESEND_FROM_EMAIL": "noreply@example.com"},
            clear=True,
        ):
            self.assertTrue(password_reset_email_configured())

    def test_incomplete_resend_configuration_does_not_enable_password_recovery(self):
        with patch.dict(os.environ, {"RESEND_API_KEY": "test-key"}, clear=True):
            self.assertFalse(password_reset_email_configured())

    @patch("email_delivery.urlopen")
    def test_resend_api_sends_password_reset_code(self, urlopen):
        response = MagicMock()
        urlopen.return_value.__enter__.return_value = response
        with patch.dict(
            os.environ,
            {"RESEND_API_KEY": "test-key", "RESEND_FROM_EMAIL": "noreply@example.com"},
            clear=True,
        ):
            send_password_reset_email("student@example.edu", "042817")

        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.resend.com/emails")
        self.assertEqual(request.get_header("Authorization"), "Bearer test-key")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(
            json.loads(request.data),
            {
                "from": "noreply@example.com",
                "to": ["student@example.edu"],
                "subject": "Your Symbiote Lofo AI password reset code",
                "text": (
                    "Your password reset verification code is: 042817\n\n"
                    "This code expires in 10 minutes. If you did not request a "
                    "password reset, you can ignore this email."
                ),
            },
        )
        urlopen.assert_called_once()
        self.assertEqual(urlopen.call_args.kwargs, {"timeout": 15})
        response.read.assert_called_once_with()

    @patch("email_delivery.smtplib.SMTP")
    def test_smtp_configuration_remains_available(self, smtp):
        with patch.dict(
            os.environ,
            {
                "SMTP_HOST": "smtp.example.com",
                "SMTP_FROM_EMAIL": "noreply@example.com",
                "SMTP_USE_TLS": "false",
            },
            clear=True,
        ):
            self.assertTrue(password_reset_email_configured())
            send_password_reset_email("student@example.edu", "042817")

        smtp.assert_called_once_with("smtp.example.com", 587, timeout=15)
        smtp.return_value.__enter__.return_value.send_message.assert_called_once()

    def test_missing_email_provider_configuration_raises(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                send_password_reset_email("student@example.edu", "042817")


if __name__ == "__main__":
    unittest.main()
