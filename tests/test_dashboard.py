import csv
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

from PyQt5.QtWidgets import QApplication, QMessageBox

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from dashboard import CanSentinelDashboard


class TestCanSentinelDashboard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication(sys.argv)

    def setUp(self):
        self.window = CanSentinelDashboard()

    def tearDown(self):
        self.window.stop_monitoring()
        self.window.close()

    def add_traffic(self, can_id="0x100", status="NORMAL"):
        self.window.traffic_records.append({
            "timestamp": "2026-10-25 10:00:00",
            "can_id": can_id,
            "payload": "01 02 03 04 05 06 07 08",
            "status": status,
        })
        self.window.message_count += 1
        self.window.update_summary()
        self.window.apply_traffic_filters()

    def add_alert(self, severity="HIGH", reason="Abnormal payload pattern"):
        self.window.alert_history.append({
            "timestamp": "2026-10-25 10:00:00",
            "can_id": "0x666",
            "severity": severity,
            "reason": reason,
            "payload": "01 02 03 04 05 06 07 08",
        })
        self.window.update_summary()
        self.window.refresh_alert_table()

    def test_filter_traffic_by_can_id(self):
        self.add_traffic("0x100")
        self.add_traffic("0x200")
        self.window.can_id_filter.setText("0x100")
        self.assertEqual(self.window.traffic_table.rowCount(), 1)

    def test_filter_traffic_by_status(self):
        self.add_traffic("0x100", "NORMAL")
        self.add_traffic("0x200", "SUSPICIOUS")
        self.window.status_filter.setCurrentText("SUSPICIOUS")
        self.assertEqual(self.window.traffic_table.rowCount(), 1)

    def test_filter_alerts_by_severity_and_reason(self):
        self.add_alert("HIGH", "Abnormal payload pattern")
        self.add_alert("LOW", "Unexpected CAN identifier")
        self.window.severity_filter.setCurrentText("HIGH")
        self.window.reason_filter.setText("payload")
        self.assertEqual(self.window.alert_table.rowCount(), 1)

    def test_clear_traffic_display_preserves_stored_records(self):
        self.add_traffic()
        with patch("dashboard.QMessageBox.information"):
            self.window.clear_traffic_display()
        self.assertEqual(self.window.traffic_table.rowCount(), 0)
        self.assertEqual(len(self.window.traffic_records), 1)

    def test_clear_alert_display_preserves_alert_history(self):
        self.add_alert()
        with patch("dashboard.QMessageBox.information"):
            self.window.clear_alert_display()
        self.assertEqual(self.window.alert_table.rowCount(), 0)
        self.assertEqual(len(self.window.alert_history), 1)

    def test_export_traffic_csv_and_row_count(self):
        self.add_traffic()
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "traffic.csv")
            with patch("dashboard.QFileDialog.getSaveFileName", return_value=(path, "CSV Files (*.csv)")), \
                 patch("dashboard.QMessageBox.information") as info:
                self.window.export_filtered_traffic()
            with open(path, newline="", encoding="utf-8-sig") as file:
                rows = list(csv.reader(file))
            self.assertEqual(rows[0], self.window.TRAFFIC_COLUMNS)
            self.assertEqual(len(rows) - 1, 1)
            self.assertIn("Exported 1 record(s)", info.call_args.args[2])

    def test_export_alert_csv_includes_severity_and_reason(self):
        self.add_alert()
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "alerts.csv")
            with patch("dashboard.QFileDialog.getSaveFileName", return_value=(path, "CSV Files (*.csv)")), \
                 patch("dashboard.QMessageBox.information"):
                self.window.export_alert_history()
            with open(path, newline="", encoding="utf-8-sig") as file:
                rows = list(csv.reader(file))
            self.assertEqual(rows[0], self.window.ALERT_COLUMNS)
            self.assertEqual(len(rows) - 1, 1)

    def test_cancel_export_does_not_create_file(self):
        with patch("dashboard.QFileDialog.getSaveFileName", return_value=("", "")):
            self.window.export_filtered_traffic()
        self.assertEqual(self.window.traffic_records, [])

    def test_clear_all_session_data_resets_records_and_counters(self):
        self.add_traffic()
        self.add_alert()
        with patch("dashboard.QMessageBox.question", return_value=QMessageBox.Yes):
            self.window.clear_all_session_data()
        self.assertEqual(self.window.traffic_records, [])
        self.assertEqual(self.window.alert_history, [])
        self.assertEqual(self.window.message_count, 0)
        self.assertEqual(self.window.alert_count, 0)
        self.assertEqual(self.window.total_value.text(), "0")
        self.assertEqual(self.window.alert_value.text(), "0")

    def test_start_and_stop_monitoring(self):
        self.window.start_monitoring()
        self.assertTrue(self.window.monitoring)
        self.assertTrue(self.window.timer.isActive())
        self.window.stop_monitoring()
        self.assertFalse(self.window.monitoring)
        self.assertFalse(self.window.timer.isActive())

    def test_demo_creates_alert_every_seventh_message(self):
        for _ in range(7):
            self.window.generate_can_message()
        self.assertEqual(len(self.window.traffic_records), 7)
        self.assertEqual(self.window.traffic_records[-1]["status"], "SUSPICIOUS")
        self.assertEqual(len(self.window.alert_history), 1)


if __name__ == "__main__":
    unittest.main()
