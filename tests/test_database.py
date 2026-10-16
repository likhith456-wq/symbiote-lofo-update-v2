import hashlib
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import database
from security import AuthorizationError, create_qr_token, hash_password, hash_qr_token


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lost-found-tests-")
        self.root = Path(self.temp.name)
        self.db_path = self.root / "test.db"
        self.data_dir = self.root
        self.photos = self.root / "item_photos"
        self.photos.mkdir()
        self._make_existing_database()
        database.migrate_database(self.db_path, self.data_dir)
        self.student = database.authenticate_user(
            self.db_path, "student@example.edu", "legacy-password"
        )
        self.admin = database.bootstrap_admin(
            self.db_path, "admin@example.edu", "admin-password-123"
        )
        self.admin = database.authenticate_user(
            self.db_path, "admin@example.edu", "admin-password-123"
        )
        self.other = database.create_student(
            self.db_path, "Other Student", "other@example.edu", hash_password("other-password-123")
        )

    def tearDown(self):
        self.temp.cleanup()

    def _make_existing_database(self):
        with closing(sqlite3.connect(self.db_path)) as conn, conn:
            conn.execute(
                """
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'student',
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    status TEXT NOT NULL,
                    item_name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    description TEXT,
                    location TEXT,
                    image_path TEXT,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE email_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_id INTEGER,
                    recipient TEXT,
                    subject TEXT,
                    sent_at TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'sent'
                )
                """
            )
            legacy_hash = hashlib.sha256(b"legacy-password").hexdigest()
            conn.execute(
                "INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                ("Student", "student@example.edu", legacy_hash, "student", "2026-10-10T10:00:00"),
            )
            conn.execute(
                """
                INSERT INTO reports(status,item_name,category,description,location,image_path,created_at)
                VALUES(?,?,?,?,?,?,?)
                """,
                (
                    "Found an Item", "wallet", "Daily-use items", "brown wallet",
                    "Library", None, "2026-10-10T11:00:00",
                ),
            )
            conn.execute(
                """
                INSERT INTO reports(status,item_name,category,description,location,image_path,created_at)
                VALUES(?,?,?,?,?,?,?)
                """,
                (
                    "Lost an Item", "keys", "Daily-use items", "blue keychain",
                    "Canteen", None, "2026-10-10T12:00:00",
                ),
            )
            conn.execute(
                "INSERT INTO email_log(report_id,recipient,subject,sent_at) VALUES(1,'student@example.edu','received','2026-10-10T11:01:00')"
            )
        (self.photos / "legacy.jpg").write_bytes(b"legacy photo")

    def test_migration_preserves_users_reports_emails_and_photos(self):
        with database.connection(self.db_path) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], 3)
            self.assertIsNotNone(
                conn.execute(
                    "SELECT id FROM users WHERE email='student@example.edu'"
                ).fetchone()
            )
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0], 2)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM email_log").fetchone()[0], 1)
            self.assertEqual(conn.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            self.assertEqual(
                conn.execute("SELECT workflow_status FROM reports WHERE id=1").fetchone()[0],
                "Open",
            )
            self.assertEqual(
                conn.execute("SELECT workflow_status FROM reports WHERE id=2").fetchone()[0],
                "Open",
            )
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM report_status_history").fetchone()[0],
                2,
            )
        backups = list((self.root / "backups").glob("migration-v4-*"))
        self.assertEqual(len(backups), 1)
        self.assertTrue((backups[0] / self.db_path.name).is_file())
        self.assertEqual(
            (backups[0] / "item_photos" / "legacy.jpg").read_bytes(), b"legacy photo"
        )

    def test_email_code_can_reset_password_and_is_rate_limited(self):
        self.assertTrue(
            database.request_password_reset_code(
                self.db_path, "student@example.edu", "042817", now=1000
            )
        )
        self.assertFalse(
            database.request_password_reset_code(
                self.db_path, "student@example.edu", "123456", now=1030
            )
        )
        self.assertFalse(
            database.reset_password(
                self.db_path,
                "student@example.edu",
                "042817",
                hash_password("new-password-123"),
                method="email",
                now=1601,
            )
        )
        self.assertTrue(
            database.request_password_reset_code(
                self.db_path, "student@example.edu", "654321", now=1601
            )
        )
        self.assertTrue(
            database.reset_password(
                self.db_path,
                "student@example.edu",
                "654321",
                hash_password("new-password-123"),
                method="email",
                now=1602,
            )
        )
        self.assertFalse(
            database.request_password_reset_code(
                self.db_path, "student@example.edu", "789012", now=1620
            )
        )
        self.assertIsNotNone(
            database.authenticate_user(
                self.db_path, "student@example.edu", "new-password-123"
            )
        )
        self.assertIsNone(
            database.authenticate_user(
                self.db_path, "student@example.edu", "legacy-password"
            )
        )

    def test_wrong_reset_codes_are_limited_and_recovery_codes_are_one_time(self):
        self.assertTrue(
            database.request_password_reset_code(
                self.db_path, "student@example.edu", "246810", now=1000
            )
        )
        for attempt in range(5):
            self.assertFalse(
                database.reset_password(
                    self.db_path,
                    "student@example.edu",
                    "wrong",
                    hash_password("new-password-123"),
                    method="email",
                    now=1001 + attempt,
                )
            )
        self.assertFalse(
            database.reset_password(
                self.db_path,
                "student@example.edu",
                "246810",
                hash_password("new-password-123"),
                method="email",
                now=1006,
            )
        )

        recovery_code = "long-random-recovery-code"
        database.replace_recovery_codes(
            self.db_path,
            self.student,
            [hash_password(recovery_code), hash_password("another-code")],
        )
        self.assertEqual(database.count_recovery_codes(self.db_path, self.student), 2)
        self.assertTrue(
            database.reset_password(
                self.db_path,
                "student@example.edu",
                recovery_code,
                hash_password("recovered-password-123"),
                method="recovery",
                now=5000,
            )
        )
        self.assertEqual(database.count_recovery_codes(self.db_path, self.student), 1)
        self.assertFalse(
            database.reset_password(
                self.db_path,
                "student@example.edu",
                recovery_code,
                hash_password("another-password-123"),
                method="recovery",
                now=5001,
            )
        )

    def test_student_queries_never_return_roll_number_or_other_reporter_id(self):
        database.update_student_profile(
            self.db_path, self.student, roll_number="0000123",
            department="Computing", year_of_study="2", phone="555",
        )
        profile = database.get_student_profile(self.db_path, self.student)
        self.assertNotIn("roll_number", profile)
        self.assertNotIn("password_hash", profile)
        database.update_student_profile(
            self.db_path, self.student, roll_number="",
            department="Computing", year_of_study="3", phone="555",
        )
        admin_profile = database.admin_search_students_by_roll(
            self.db_path, self.admin, "0000123", time.time()
        )
        self.assertEqual(admin_profile[0]["roll_number"], "0000123")
        database.save_report(
            self.db_path, self.student, "Lost", "wallet", "Daily-use items",
            "Brown wallet", "Library", None,
        )
        campus_reports = database.list_reports(self.db_path, self.student)
        self.assertTrue(campus_reports)
        self.assertNotIn("reporter_id", campus_reports[0])
        own_reports = database.list_reports(self.db_path, self.student, own_only=True)
        self.assertNotIn("roll_number", own_reports[0])
        self.assertNotIn("password_hash", own_reports[0])

    def test_only_recently_reauthenticated_admin_can_search_roll_number(self):
        database.update_student_profile(
            self.db_path, self.student, roll_number="0000123",
            department="Computing", year_of_study="2", phone="",
        )
        with self.assertRaises(AuthorizationError):
            database.admin_search_students_by_roll(
                self.db_path, self.student, "0000123", time.time()
            )
        with self.assertRaises(AuthorizationError):
            database.admin_search_students_by_roll(
                self.db_path, {"id": -1}, "0000123", time.time()
            )
        with self.assertRaises(AuthorizationError):
            database.admin_search_students_by_roll(
                self.db_path, self.admin, "0000123", time.time() - 600
            )
        results = database.admin_search_students_by_roll(
            self.db_path, self.admin, "0000123", time.time()
        )
        self.assertEqual(results[0]["roll_number"], "0000123")

    def test_configured_roll_format_and_uniqueness(self):
        with patch.dict(os.environ, {"ROLL_NUMBER_REGEX": r"[A-Z][0-9]{4}", "ROLL_NUMBER_UNIQUE": "true"}):
            with self.assertRaises(ValueError):
                database.update_student_profile(
                    self.db_path, self.student, roll_number="0000123",
                    department="", year_of_study="", phone="",
                )
            database.update_student_profile(
                self.db_path, self.student, roll_number="A0001",
                department="", year_of_study="", phone="",
            )
            with self.assertRaises(ValueError):
                database.update_student_profile(
                    self.db_path, self.other, roll_number="A0001",
                    department="", year_of_study="", phone="",
                )

    def test_migration_refuses_duplicate_rolls_without_changing_source(self):
        duplicate_db = self.root / "duplicate-roll.db"
        with closing(sqlite3.connect(duplicate_db)) as conn, conn:
            conn.execute(
                "CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT, email TEXT, password_hash TEXT, role TEXT, created_at TEXT, roll_number TEXT)"
            )
            conn.executemany(
                "INSERT INTO users VALUES(?,?,?,?,?,?,?)",
                [
                    (1, "One", "one@example.edu", "x", "student", "today", "A1"),
                    (2, "Two", "two@example.edu", "x", "student", "today", "A1"),
                ],
            )
        with patch.dict(os.environ, {"ROLL_NUMBER_UNIQUE": "true"}):
            with self.assertRaises(RuntimeError):
                database.migrate_database(duplicate_db, self.root / "duplicate-data")
        with closing(sqlite3.connect(duplicate_db)) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], 2)
            self.assertIsNone(
                conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
                ).fetchone()
            )

    def test_signup_is_always_student(self):
        self.assertEqual(self.other["role"], "student")

    def test_admin_signup_accepts_any_email_without_promoting_existing_students(self):
        with self.assertRaises(sqlite3.IntegrityError):
            database.create_admin(
                self.db_path,
                "Other Student",
                "other@example.edu",
                hash_password("different-password-123"),
            )
        self.assertEqual(
            database.find_user_by_email(self.db_path, "other@example.edu")["role"],
            "student",
        )
        admin = database.create_admin(
            self.db_path,
            "New Admin",
            " New-Admin@example.edu ",
            hash_password("new-admin-password-123"),
        )
        self.assertEqual(admin["role"], "admin")

    def test_migration_removes_legacy_admin_signup_otp_table(self):
        with database.connection(self.db_path) as conn:
            self.assertIsNone(
                conn.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name='admin_signup_otps'"
                ).fetchone()
            )
            self.assertEqual(
                conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0],
                4,
            )

    def test_qr_tokens_are_private_and_revocable(self):
        token = create_qr_token()
        item_id = database.create_registered_item(
            self.db_path,
            self.student,
            item_name="Laptop",
            category="Electronics",
            detailed_description="Private identifying details",
            serial_number="PRIVATE-SERIAL",
            qr_token_hash=hash_qr_token(token),
        )
        self.assertTrue(database.lookup_public_qr(self.db_path, token))
        self.assertFalse(database.lookup_public_qr(self.db_path, "invalid"))
        student_items = database.list_registered_items(self.db_path, self.student)
        self.assertEqual(student_items[0]["serial_number"], "PRIVATE-SERIAL")
        with self.assertRaises(AuthorizationError):
            database.list_registered_items(
                self.db_path, self.other, owner_id=self.student["id"]
            )
        with self.assertRaises(AuthorizationError):
            database.list_registered_items(self.db_path, self.admin, reauthenticated_at=time.time()-400)
        private = database.get_registered_item(self.db_path, self.student, item_id)
        self.assertNotIn("qr_token_hash", private)
        with self.assertRaises(AuthorizationError):
            database.get_registered_item(self.db_path, self.other, item_id)
        database.deactivate_registered_item(self.db_path, self.student, item_id)
        self.assertFalse(database.lookup_public_qr(self.db_path, token))

    def test_multiple_claims_are_private_and_admin_only_to_review(self):
        found_id = database.save_report(
            self.db_path, self.student, "Found", "wallet", "Daily-use items",
            "Blue wallet", "Library", None,
        )
        lost_one = database.save_report(
            self.db_path, self.other, "Lost", "wallet", "Daily-use items",
            "My wallet", "Library", None,
        )
        claim_one = database.create_claim(
            self.db_path, self.other, found_id, "Secret stitching detail", lost_one
        )
        claim_two = database.create_claim(
            self.db_path, self.student, found_id, "A second private proof"
        )
        self.assertEqual(len(database.list_my_claims(self.db_path, self.other)), 1)
        with self.assertRaises(AuthorizationError):
            database.list_admin_claims(self.db_path, self.other, time.time())
        with self.assertRaises(AuthorizationError):
            database.review_claim(
                self.db_path, self.other, claim_one, "Approved", "no", time.time()
            )
        claims = database.list_admin_claims(self.db_path, self.admin, time.time())
        self.assertEqual(len(claims), 2)
        self.assertEqual({claim["id"] for claim in claims}, {claim_one, claim_two})

    def test_handover_is_atomic_and_closes_other_pending_claims(self):
        found_id = database.save_report(
            self.db_path, self.student, "Found", "backpack", "Bags",
            "Green bag", "Canteen", None,
        )
        claim_one = database.create_claim(self.db_path, self.other, found_id, "Proof one")
        claim_two = database.create_claim(self.db_path, self.student, found_id, "Proof two")
        now = time.time()
        database.review_claim(self.db_path, self.admin, claim_one, "Approved", "Verified", now)
        with self.assertRaises(ValueError):
            database.review_claim(self.db_path, self.admin, claim_two, "Approved", "Also verified", now)
        database.complete_handover(self.db_path, self.admin, claim_one, "ID checked", now)
        with self.assertRaises(ValueError):
            database.complete_handover(self.db_path, self.admin, claim_one, "again", now)
        with database.connection(self.db_path) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM handovers").fetchone()[0], 1)
            self.assertEqual(
                conn.execute("SELECT workflow_status FROM reports WHERE id=?", (found_id,)).fetchone()[0],
                "Returned",
            )
            self.assertEqual(
                conn.execute("SELECT status FROM claims WHERE id=?", (claim_two,)).fetchone()[0],
                "Rejected",
            )
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] > 0, True)

    def test_two_concurrent_handover_attempts_create_at_most_one(self):
        found_id = database.save_report(
            self.db_path, self.student, "Found", "phone", "Electronics",
            "Phone", "Block A", None,
        )
        claim_id = database.create_claim(self.db_path, self.other, found_id, "Proof")
        database.review_claim(
            self.db_path, self.admin, claim_id, "Approved", "Verified", time.time()
        )
        barrier = threading.Barrier(2)

        def attempt():
            barrier.wait()
            try:
                database.complete_handover(
                    self.db_path, self.admin, claim_id, "Verified", time.time()
                )
                return "success"
            except (ValueError, sqlite3.IntegrityError):
                return "conflict"

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: attempt(), range(2)))
        self.assertEqual(results.count("success"), 1)
        with database.connection(self.db_path) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM handovers").fetchone()[0], 1)

    def test_duplicate_warnings_are_reporter_scoped_and_do_not_delete(self):
        report_id = database.save_report(
            self.db_path, self.student, "Lost", "water bottle", "Daily-use items",
            "Blue metal bottle", "Library", None,
        )
        database.save_report(
            self.db_path, self.other, "Lost", "water bottle", "Daily-use items",
            "Blue metal bottle", "Library", None,
        )
        matches = database.find_duplicate_reports(
            self.db_path, self.student, "Lost", "water bottle",
            "Daily-use items", "Blue metal bottle", "Library", "1900-01-01",
        )
        self.assertEqual([row["id"] for row in matches], [report_id])
        self.assertNotIn("reporter_id", matches[0])
        with database.connection(self.db_path) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0], 4)

    def test_workflow_transitions_are_authorized_and_audited(self):
        report_id = database.save_report(
            self.db_path, self.student, "Lost", "keys", "Daily-use items",
            "Keys", "Gym", None,
        )
        with self.assertRaises(AuthorizationError):
            database.update_workflow_status(self.db_path, self.student, report_id, "Under Review")
        database.update_workflow_status(
            self.db_path, self.admin, report_id, "Under Review", "Checking desk"
        )
        own_history = database.get_status_history(self.db_path, self.student, report_id)
        self.assertNotIn("admin_note", own_history[-1])
        admin_history = database.get_status_history(
            self.db_path, self.admin, report_id, admin=True, reauthenticated_at=time.time()
        )
        self.assertEqual(admin_history[-1]["admin_note"], "Checking desk")


if __name__ == "__main__":
    unittest.main()
