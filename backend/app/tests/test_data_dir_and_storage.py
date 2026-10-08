import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from unittest.mock import patch

from app.config.config import Settings
from app.database.feedback import init_db as init_feedback_db, save_feedback, read_feedback_records, get_db_path as get_feedback_db_path
from app.engines.sender_engine import init_db as init_sender_db, _analyze_sender_internal, get_sender_db_path
from app.models.feedback import FeedbackRequest


class TestDataDirAndStorage(unittest.TestCase):
    def test_custom_data_dir_creates_clean_databases_on_boot(self):
        """When DATA_DIR points to a new or empty directory, the backend boots cleanly and creates tables."""
        with tempfile.TemporaryDirectory() as temp_dir:
            custom_data_dir = os.path.join(temp_dir, "custom_store")
            self.assertFalse(os.path.exists(custom_data_dir))

            with patch.dict(os.environ, {"DATA_DIR": custom_data_dir}):
                settings = Settings()
                self.assertEqual(settings.resolved_data_dir, os.path.abspath(custom_data_dir))

                # 1. Initialize empty DBs
                init_feedback_db()
                init_sender_db()

                feedback_db = get_feedback_db_path()
                sender_db = get_sender_db_path()

                self.assertTrue(os.path.exists(feedback_db))
                self.assertTrue(os.path.exists(sender_db))

                # 2. Verify feedback table schema exists and is ready
                with closing(sqlite3.connect(feedback_db)) as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='feedback'")
                    self.assertIsNotNone(cursor.fetchone())

                # 3. Verify sender tables schema exists and is ready
                with closing(sqlite3.connect(sender_db)) as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='senders'")
                    self.assertIsNotNone(cursor.fetchone())
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sender_name_history'")
                    self.assertIsNotNone(cursor.fetchone())

                # 4. Verify save & read on clean DB
                saved, _ = save_feedback(
                    FeedbackRequest(
                        scan_id="12345678-1234-1234-1234-123456789abc",
                        user_feedback="positive",
                        classification_at_scan_time="Safe",
                        risk_score_at_scan_time=5.0,
                        confidence_at_scan_time=0.9,
                        source_type="url",
                    )
                )
                self.assertTrue(saved)
                records = read_feedback_records()
                self.assertEqual(len(records), 1)

                # 5. Verify sender analysis on clean DB
                analysis = _analyze_sender_internal("alice@example.com")
                self.assertIsInstance(analysis, dict)


if __name__ == "__main__":
    unittest.main()
