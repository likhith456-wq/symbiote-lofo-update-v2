import os
import unittest
from datetime import date
from unittest.mock import patch

from security import (
    create_qr_token,
    create_recovery_codes,
    hash_password,
    hash_qr_token,
    is_under_age,
    meets_minimum_age,
    validate_roll_number,
    verify_password,
)


class SecurityTests(unittest.TestCase):
    def test_password_hash_is_salted_and_verifies(self):
        first = hash_password("a sufficiently long password")
        second = hash_password("a sufficiently long password")
        self.assertNotEqual(first, second)
        self.assertTrue(verify_password("a sufficiently long password", first)[0])
        self.assertFalse(verify_password("wrong", first)[0])

    def test_legacy_password_is_verified_and_marked_for_upgrade(self):
        import hashlib

        legacy = hashlib.sha256(b"legacy-password").hexdigest()
        self.assertEqual(
            verify_password("legacy-password", legacy),
            (True, True),
        )

    def test_roll_number_is_kept_as_a_string_and_optional_rule_is_configurable(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(validate_roll_number("  00042 "), "00042")
        with patch.dict(os.environ, {"ROLL_NUMBER_REGEX": r"[0-9]{5}"}, clear=True):
            self.assertEqual(validate_roll_number("00042"), "00042")
            with self.assertRaises(ValueError):
                validate_roll_number("42")

    def test_qr_token_is_random_and_only_hash_is_stored(self):
        token = create_qr_token()
        self.assertGreaterEqual(len(token), 40)
        self.assertNotEqual(token, hash_qr_token(token))
        self.assertNotEqual(hash_qr_token(token), hash_qr_token(create_qr_token()))

    def test_password_recovery_credential_generators(self):
        codes = create_recovery_codes()
        self.assertEqual(len(codes), 10)
        self.assertEqual(len(set(codes)), 10)
        self.assertTrue(all(len(code) >= 16 for code in codes))

    def test_age_check_enforces_exact_birthday_and_rejects_future_dates(self):
        today = date(2026, 10, 13)
        self.assertTrue(meets_minimum_age(date(2003, 10, 13), 23, today=today))
        self.assertFalse(meets_minimum_age(date(2003, 10, 14), 23, today=today))
        self.assertFalse(meets_minimum_age(date(2027, 1, 1), 23, today=today))
        self.assertFalse(meets_minimum_age("2000-01-01", 23, today=today))

    def test_student_signup_age_must_be_strictly_under_23(self):
        today = date(2026, 10, 13)
        self.assertTrue(is_under_age(date(2003, 10, 14), 23, today=today))
        self.assertFalse(is_under_age(date(2003, 10, 13), 23, today=today))
        self.assertFalse(is_under_age(date(2027, 1, 1), 23, today=today))
        self.assertFalse(is_under_age("2000-01-01", 23, today=today))


if __name__ == "__main__":
    unittest.main()
