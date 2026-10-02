import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient

from main import app


class TestFeedbackEvaluationAPI(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "feedback.db")
        self.db_path_patch = patch("app.database.feedback.DB_PATH", self.db_path)
        self.db_path_patch.start()
        self.client = TestClient(app)

    def tearDown(self):
        self.client.close()
        self.db_path_patch.stop()
        self.temp_dir.cleanup()

    @staticmethod
    def request(scan_id=None, **overrides):
        payload = {
            "scan_id": scan_id or str(uuid4()),
            "user_feedback": "positive",
            "classification_at_scan_time": "Safe",
            "risk_score_at_scan_time": 12.5,
            "confidence_at_scan_time": 0.8,
            "source_type": "url",
        }
        payload.update(overrides)
        return payload

    def test_positive_feedback_is_saved_without_scan_content(self):
        payload = self.request()
        response = self.client.post("/api/feedback", json=payload)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "success")
        self.assertEqual(response.json()["scan_id"], payload["scan_id"])
        self.assertNotIn("text", response.json())
        self.assertNotIn("target", response.json())

        with closing(sqlite3.connect(self.db_path)) as connection:
            stored = connection.execute(
                "SELECT target, user_feedback, classification_at_scan_time, risk_score_at_scan_time, "
                "confidence_at_scan_time, source_type FROM feedback WHERE scan_id = ?",
                (payload["scan_id"],),
            ).fetchone()
        self.assertEqual(stored, (payload["scan_id"], "positive", "Safe", 12.5, 0.8, "url"))

    def test_negative_feedback_and_legacy_phase9_request_are_supported(self):
        negative = self.request(user_feedback="negative", source_type="gmail")
        response = self.client.post("/api/feedback", json=negative)
        self.assertEqual(response.status_code, 200)

        legacy_scan_id = str(uuid4())
        legacy = {
            "analyzed_target": legacy_scan_id,
            "score": 80,
            "category": "Phishing",
            "feedback_value": "down",
        }
        legacy_response = self.client.post("/api/feedback", json=legacy)
        self.assertEqual(legacy_response.status_code, 200)

        with closing(sqlite3.connect(self.db_path)) as connection:
            normalized = connection.execute(
                "SELECT scan_id, user_feedback, confidence_at_scan_time, source_type "
                "FROM feedback WHERE scan_id = ?",
                (legacy_scan_id,),
            ).fetchone()
        self.assertEqual(normalized, (legacy_scan_id, "negative", 0.0, "unknown"))

    def test_invalid_value_malformed_requests_and_ranges_are_rejected(self):
        invalid_value = self.client.post("/api/feedback", json=self.request(user_feedback="up"))
        malformed = self.client.post("/api/feedback", json={"scan_id": str(uuid4())})
        raw_content = self.client.post("/api/feedback", json=self.request(raw_email_body="private body"))
        invalid_score = self.client.post("/api/feedback", json=self.request(risk_score_at_scan_time=101))
        invalid_confidence = self.client.post("/api/feedback", json=self.request(confidence_at_scan_time=-0.1))
        invalid_id = self.client.post("/api/feedback", json=self.request(scan_id="not-a-uuid"))

        self.assertEqual(invalid_value.status_code, 422)
        self.assertEqual(malformed.status_code, 422)
        self.assertEqual(raw_content.status_code, 422)
        self.assertNotIn("private body", raw_content.text)
        self.assertNotIn("not-a-uuid", invalid_id.text)
        self.assertEqual(raw_content.json()["detail"]["code"], "invalid_feedback_request")
        self.assertEqual(invalid_score.status_code, 422)
        self.assertEqual(invalid_confidence.status_code, 422)
        self.assertEqual(invalid_id.status_code, 422)

    def test_duplicate_scan_feedback_is_rejected(self):
        scan_id = str(uuid4())
        self.assertEqual(self.client.post("/api/feedback", json=self.request(scan_id)).status_code, 200)
        duplicate = self.client.post("/api/feedback", json=self.request(scan_id, user_feedback="negative"))

        self.assertEqual(duplicate.status_code, 409)
        self.assertEqual(duplicate.json()["detail"]["code"], "duplicate_feedback")

    def test_legacy_feedback_table_is_migrated_without_dropping_rows(self):
        with closing(sqlite3.connect(self.db_path)) as connection:
            connection.execute(
                """CREATE TABLE feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT,
                    score INTEGER,
                    category TEXT,
                    feedback_value TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )"""
            )
            connection.execute(
                "INSERT INTO feedback (target, score, category, feedback_value) VALUES (?, ?, ?, ?)",
                ("legacy-record", 30, "Suspicious", "up"),
            )
            connection.commit()

        payload = self.request(classification_at_scan_time="Phishing", source_type="gmail")
        response = self.client.post("/api/feedback", json=payload)
        self.assertEqual(response.status_code, 200)

        with closing(sqlite3.connect(self.db_path)) as connection:
            columns = {row[1] for row in connection.execute("PRAGMA table_info(feedback)")}
            legacy_record = connection.execute(
                "SELECT target, score, category, feedback_value FROM feedback WHERE target = ?",
                ("legacy-record",),
            ).fetchone()
            normalized_count = connection.execute(
                "SELECT COUNT(*) FROM feedback WHERE scan_id IS NOT NULL"
            ).fetchone()[0]
        self.assertTrue({"scan_id", "user_feedback", "confidence_at_scan_time", "source_type"}.issubset(columns))
        self.assertEqual(legacy_record, ("legacy-record", 30, "Suspicious", "up"))
        self.assertEqual(normalized_count, 1)

    def test_new_schema_rejects_invalid_values_at_sqlite_boundary(self):
        from app.database.feedback import init_db

        init_db(self.db_path)
        with closing(sqlite3.connect(self.db_path)) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """INSERT INTO feedback (
                        scan_id, user_feedback, classification_at_scan_time,
                        risk_score_at_scan_time, confidence_at_scan_time, source_type
                    ) VALUES (?, ?, ?, ?, ?, ?)""",
                    (str(uuid4()), "unknown", "Safe", 101, 0.5, "url"),
                )

    def test_zero_feedback_metrics_are_well_formed(self):
        response = self.client.get("/api/evaluation/metrics")

        self.assertEqual(response.status_code, 200)
        metrics = response.json()
        self.assertEqual(metrics["total_feedback_count"], 0)
        self.assertEqual(metrics["positive_feedback_count"], 0)
        self.assertEqual(metrics["negative_feedback_count"], 0)
        self.assertEqual(metrics["positive_feedback_rate"], 0)
        self.assertEqual(metrics["negative_feedback_rate"], 0)
        self.assertIsNone(metrics["average_risk_score_positive"])
        self.assertIsNone(metrics["average_risk_score_negative"])
        self.assertEqual(set(metrics["classification_feedback_summary"]), {"Safe", "Suspicious", "Deceptive", "Phishing", "Malware"})

    def test_multiple_records_aggregate_classification_source_and_risk(self):
        cases = [
            self.request(classification_at_scan_time="Safe", risk_score_at_scan_time=10, source_type="url"),
            self.request(user_feedback="negative", classification_at_scan_time="Safe", risk_score_at_scan_time=30, source_type="url"),
            self.request(classification_at_scan_time="Phishing", risk_score_at_scan_time=90, source_type="gmail"),
            self.request(user_feedback="negative", classification_at_scan_time="Malware", risk_score_at_scan_time=95, source_type="file"),
        ]
        for payload in cases:
            self.assertEqual(self.client.post("/api/feedback", json=payload).status_code, 200)

        metrics = self.client.get("/api/evaluation/metrics").json()
        self.assertEqual(metrics["total_feedback_count"], 4)
        self.assertEqual(metrics["positive_feedback_count"], 2)
        self.assertEqual(metrics["negative_feedback_count"], 2)
        self.assertEqual(metrics["positive_feedback_rate"], 0.5)
        self.assertEqual(metrics["negative_feedback_rate"], 0.5)
        self.assertEqual(metrics["feedback_count_by_classification"]["Safe"], 2)
        self.assertEqual(metrics["feedback_count_by_source_type"]["url"], 2)
        self.assertEqual(metrics["feedback_count_by_source_type"]["gmail"], 1)
        self.assertEqual(metrics["feedback_count_by_source_type"]["file"], 1)
        self.assertEqual(metrics["average_risk_score_positive"], 50)
        self.assertEqual(metrics["average_risk_score_negative"], 62.5)
        self.assertEqual(metrics["classification_feedback_summary"]["Safe"]["positive_count"], 1)
        self.assertEqual(metrics["classification_feedback_summary"]["Safe"]["negative_count"], 1)
        self.assertNotIn("scan_id", metrics)
        self.assertNotIn("target", metrics)

    def test_database_failures_return_service_unavailable(self):
        with patch("app.database.feedback.DB_PATH", self.temp_dir.name):
            submit = self.client.post("/api/feedback", json=self.request())
            metrics = self.client.get("/api/evaluation/metrics")

        self.assertEqual(submit.status_code, 503)
        self.assertEqual(submit.json()["detail"]["code"], "feedback_storage_unavailable")
        self.assertEqual(metrics.status_code, 503)


if __name__ == "__main__":
    unittest.main(verbosity=2)