import csv
import os
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtWidgets import QApplication
from dashboard import CanSentinelDashboard


class TestDashboardIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.window = CanSentinelDashboard()

    def tearDown(self):
        self.window.stop_monitoring()
        self.window.close()

    def test_seventh_message_creates_high_alert_and_updates_summary(self):
        for _ in range(7):
            self.window.generate_can_message()
        self.assertEqual(len(self.window.traffic_records), 7)
        self.assertEqual(len(self.window.alert_history), 1)
        self.assertEqual(self.window.alert_history[0]["severity"], "HIGH")
        self.assertEqual(self.window.total_value.text(), "7")
        self.assertEqual(self.window.alert_value.text(), "1")
        self.assertEqual(self.window.normal_value.text(), "6")

    def test_traffic_filters_by_can_id_and_status(self):
        self.window.traffic_records = [
            {"timestamp": "2026-10-15 10:00:00", "can_id": "0x100",
             "payload": "01 02 03 04 05 06 07 08", "status": "NORMAL"},
            {"timestamp": "2026-10-15 10:00:01", "can_id": "0x666",
             "payload": "AA BB CC DD EE FF 00 11", "status": "SUSPICIOUS"},
        ]
        self.window.can_id_filter.setText("0x666")
        self.window.status_filter.setCurrentText("SUSPICIOUS")
        self.window.apply_traffic_filters()
        self.assertEqual(self.window.traffic_table.rowCount(), 1)
        self.assertEqual(self.window.traffic_table.item(0, 1).text(), "0x666")
        self.assertEqual(self.window.traffic_table.item(0, 3).text(), "SUSPICIOUS")

    def test_clear_display_does_not_delete_exportable_records(self):
        self.window.generate_can_message()
        count_before = len(self.window.traffic_records)
        with patch("dashboard.QMessageBox.information"):
            self.window.clear_traffic_display()
        self.assertEqual(len(self.window.traffic_records), count_before)
        self.assertEqual(self.window.traffic_table.rowCount(), 0)

    def test_alert_filters_by_severity_and_reason(self):
        self.window.alert_history = [
            {"timestamp": "2026-10-15 10:00:00", "can_id": "0x666",
             "severity": "HIGH", "reason": "Suspicious demo message", "payload": "AA BB"},
            {"timestamp": "2026-10-15 10:00:01", "can_id": "0x321",
             "severity": "LOW", "reason": "Manual review", "payload": "00 11"},
        ]
        self.window.severity_filter.setCurrentText("HIGH")
        self.window.reason_filter.setText("demo")
        self.window.refresh_alert_table()
        self.assertEqual(self.window.alert_table.rowCount(), 1)
        self.assertEqual(self.window.alert_table.item(0, 2).text(), "HIGH")

    def test_csv_writer_writes_header_and_data(self):
        # Day 6A adds these small helpers to dashboard.py (see PATCH_NOTES.md).
        rows = [["2026-10-15 10:00:00", "0x100", "01 02 03 04 05 06 07 08", "NORMAL"]]
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "traffic.csv")
            count = self.window._write_csv(path, self.window.TRAFFIC_COLUMNS, rows)
            self.assertEqual(count, 1)
            with open(path, newline="", encoding="utf-8-sig") as file:
                saved = list(csv.reader(file))
        self.assertEqual(saved[0], ["Timestamp", "CAN ID", "Payload", "Status"])
        self.assertEqual(saved[1], rows[0])

    def test_csv_extension_is_added_only_when_missing(self):
        self.assertEqual(self.window._append_csv_extension("traffic"), "traffic.csv")
        self.assertEqual(self.window._append_csv_extension("traffic.csv"), "traffic.csv")
        self.assertEqual(self.window._append_csv_extension("traffic.CSV"), "traffic.CSV")


if __name__ == "__main__":
    unittest.main(verbosity=2)
