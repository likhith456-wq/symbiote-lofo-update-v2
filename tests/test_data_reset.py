import json
import tempfile
import unittest
from pathlib import Path

from data_reset import reset_app_data_once


class DataResetTests(unittest.TestCase):
    confirmation = "DELETE_ALL_APP_DATA"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="app-data-reset-")
        self.root = Path(self.temp.name)
        (self.root / "lost_found.db").write_text("database", encoding="utf-8")
        (self.root / "lost_found.db-wal").write_text("wal", encoding="utf-8")
        (self.root / "lost_found.db-shm").write_text("shm", encoding="utf-8")
        (self.root / "item_photos").mkdir()
        (self.root / "item_photos" / "photo.jpg").write_bytes(b"photo")
        (self.root / "backups").mkdir()
        (self.root / "backups" / "backup.db").write_bytes(b"backup")
        (self.root / "huggingface").mkdir()
        (self.root / "huggingface" / "model.bin").write_bytes(b"model")

    def tearDown(self):
        self.temp.cleanup()

    def test_reset_removes_app_records_and_uploads_only(self):
        self.assertTrue(
            reset_app_data_once(self.root, "a" * 32, self.confirmation)
        )

        for name in (
            "lost_found.db",
            "lost_found.db-wal",
            "lost_found.db-shm",
            "item_photos",
            "backups",
        ):
            self.assertFalse((self.root / name).exists())
        self.assertEqual(
            (self.root / "huggingface" / "model.bin").read_bytes(),
            b"model",
        )

    def test_same_token_does_not_reset_new_data_again(self):
        token = "b" * 32
        self.assertTrue(reset_app_data_once(self.root, token, self.confirmation))
        (self.root / "lost_found.db").write_text("fresh database", encoding="utf-8")

        self.assertFalse(reset_app_data_once(self.root, token, self.confirmation))
        self.assertEqual(
            (self.root / "lost_found.db").read_text(encoding="utf-8"),
            "fresh database",
        )

    def test_new_token_requests_a_new_one_time_reset(self):
        self.assertTrue(
            reset_app_data_once(self.root, "c" * 32, self.confirmation)
        )
        (self.root / "lost_found.db").write_text("new data", encoding="utf-8")

        self.assertTrue(
            reset_app_data_once(self.root, "d" * 32, self.confirmation)
        )
        self.assertFalse((self.root / "lost_found.db").exists())

    def test_reset_requires_a_long_token_before_removing_anything(self):
        with self.assertRaisesRegex(ValueError, "at least 32"):
            reset_app_data_once(self.root, "short", self.confirmation)
        self.assertTrue((self.root / "lost_found.db").exists())

    def test_empty_token_does_not_reset_data(self):
        self.assertFalse(
            reset_app_data_once(self.root, "", self.confirmation)
        )
        self.assertTrue((self.root / "lost_found.db").exists())

    def test_corrupt_marker_stops_without_removing_data(self):
        (self.root / ".app-data-reset.json").write_text("{", encoding="utf-8")
        with self.assertRaises(json.JSONDecodeError):
            reset_app_data_once(self.root, "e" * 32, self.confirmation)
        self.assertTrue((self.root / "lost_found.db").exists())

    def test_reset_requires_explicit_confirmation(self):
        with self.assertRaisesRegex(ValueError, "RESET_APP_DATA_CONFIRM"):
            reset_app_data_once(self.root, "f" * 32, "yes")
        self.assertTrue((self.root / "lost_found.db").exists())


if __name__ == "__main__":
    unittest.main()
