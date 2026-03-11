import os
import tempfile
import unittest
import time
from datetime import datetime, timezone

from datastore import (
    add_scan_alert,
    get_all_scan_alerts,
    get_scan_alerts,
    init_db,
    save_scan,
    update_scan_alert_status,
)


class DatastoreTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_osint.db")
        init_db(self.db_path)

    def tearDown(self):
        for _ in range(5):
            try:
                self.temp_dir.cleanup()
                break
            except PermissionError:
                time.sleep(0.05)

    def _sample_result(self, username: str = "alice"):
        return {
            "username": username,
            "queried_at": datetime.now(timezone.utc).isoformat(),
            "profile_status": {
                "GitHub": {"exists": True, "status": 200},
                "Reddit": {"exists": False, "status": 404},
            },
            "risk_assessment": {"score": 65.0, "level": "Medium"},
        }

    def test_save_scan_skips_recent_duplicate(self):
        first_saved = save_scan(self._sample_result(), path=self.db_path, skip_duplicate_days=7)
        second_saved = save_scan(self._sample_result(), path=self.db_path, skip_duplicate_days=7)

        self.assertTrue(first_saved)
        self.assertFalse(second_saved)

    def test_alert_lifecycle(self):
        save_scan(self._sample_result(), path=self.db_path, skip_duplicate_days=0)
        alert_added = add_scan_alert(1, "HIGH_RISK_SCORE", "Risk elevato", severity="HIGH", path=self.db_path)
        scan_alerts = get_scan_alerts(1, path=self.db_path)

        self.assertTrue(alert_added)
        self.assertEqual(len(scan_alerts), 1)
        self.assertEqual(scan_alerts[0]["severity"], "HIGH")
        self.assertEqual(scan_alerts[0]["status"], "OPEN")

        updated = update_scan_alert_status(scan_alerts[0]["id"], "RESOLVED", path=self.db_path)
        history = get_all_scan_alerts(status="RESOLVED", path=self.db_path)

        self.assertTrue(updated)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["status"], "RESOLVED")


if __name__ == "__main__":
    unittest.main()