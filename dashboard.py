import sys
import csv
import random
from datetime import datetime
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QTableWidget, QTableWidgetItem, QLineEdit,
    QComboBox, QFileDialog, QMessageBox, QFrame, QHeaderView, QTabWidget
)
class CanSentinelDashboard(QMainWindow):
    # Display colors are visual aids for simulated demo severity levels.
    SEVERITY_COLORS = {
        "LOW": ("#5ce0a0", "#173b32"),
        "MEDIUM": ("#f4d35e", "#443b1b"),
        "HIGH": ("#ff9f43", "#492d1c"),
        "CRITICAL": ("#ff6b6b", "#4a2028"),
    }
    TRAFFIC_COLUMNS = ["Timestamp", "CAN ID", "Payload", "Status"]
    ALERT_COLUMNS = ["Timestamp", "CAN ID", "Severity", "Reason", "Payload"]
    @staticmethod
    def _append_csv_extension(path):
        """Add the .csv extension only if the filename does not already have it."""
        return path if path.lower().endswith(".csv") else path + ".csv"
    @staticmethod
    def _write_csv(path, columns, rows):
        """Write a CSV header and rows; return the number of data rows written.
        Rows may be sequences or dictionaries. For dictionaries, the header labels
        are mapped to the dashboard's record keys.
        """
        key_map = {
            "Timestamp": "timestamp",
            "CAN ID": "can_id",
            "Payload": "payload",
            "Status": "status",
            "Severity": "severity",
            "Reason": "reason",
        }
        count = 0
        with open(path, "w", newline="", encoding="utf-8-sig") as file:
            writer = csv.writer(file)
            writer.writerow(columns)
            for row in rows:
                if isinstance(row, dict):
                    writer.writerow([row.get(key_map.get(col, col), "") for col in columns])
                else:
                    writer.writerow(row)
                count += 1
        return count
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CAN-Sentinel | Automotive ECU Intrusion Detection")
        self.resize(1280, 820)
        # Traffic records and alert history are deliberately stored separately.
        # Clearing the visible display does not delete the persistent-in-session
        # records used by CSV export.
        self.traffic_records = []
        self.alert_history = []
        self.message_count = 0
        self.alert_count = 0
        self.monitoring = False
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.generate_can_message)
        self.build_ui()
        self.update_summary()
    def build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(18, 16, 18, 16)
        outer.setSpacing(12)
        header = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("CAN-SENTINEL")
        title.setObjectName("mainTitle")
        subtitle = QLabel("Automotive ECU Intrusion Detection System • Demonstration Mode")
        subtitle.setObjectName("subtitle")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header.addLayout(title_box)
        header.addStretch()
        self.status_label = QLabel("● STOPPED")
        self.status_label.setObjectName("statusStopped")
        header.addWidget(self.status_label)
        outer.addLayout(header)
        summary = QGridLayout()
        summary.setSpacing(10)
        self.total_card, self.total_value = self.make_card("TOTAL CAN MESSAGES")
        self.alert_card, self.alert_value = self.make_card("TOTAL ALERTS")
        self.normal_card, self.normal_value = self.make_card("NORMAL MESSAGES")
        self.threat_card, self.threat_value = self.make_card("LATEST ALERT")
        summary.addWidget(self.total_card, 0, 0)
        summary.addWidget(self.alert_card, 0, 1)
        summary.addWidget(self.normal_card, 0, 2)
        summary.addWidget(self.threat_card, 0, 3)
        outer.addLayout(summary)
        controls = QHBoxLayout()
        self.start_button = QPushButton("▶ Start Monitoring")
        self.start_button.setObjectName("primaryButton")
        self.start_button.clicked.connect(self.start_monitoring)
        self.stop_button = QPushButton("■ Stop Monitoring")
        self.stop_button.clicked.connect(self.stop_monitoring)
        self.clear_display_button = QPushButton("Clear Traffic Display")
        self.clear_display_button.setToolTip(
            "Clears the visible traffic table only. Stored traffic and alert history remain available for CSV export."
        )
        self.clear_display_button.clicked.connect(self.clear_traffic_display)
        self.clear_all_button = QPushButton("Clear All Session Data")
        self.clear_all_button.setObjectName("dangerButton")
        self.clear_all_button.setToolTip(
            "Permanently clears traffic and alert records from this running session."
        )
        self.clear_all_button.clicked.connect(self.clear_all_session_data)
        controls.addWidget(self.start_button)
        controls.addWidget(self.stop_button)
        controls.addWidget(self.clear_display_button)
        controls.addWidget(self.clear_all_button)
        controls.addStretch()
        outer.addLayout(controls)
        self.tabs = QTabWidget()
        outer.addWidget(self.tabs, 1)
        # Traffic tab retains Day 4 filtering and CSV export.
        traffic_tab = QWidget()
        traffic_layout = QVBoxLayout(traffic_tab)
        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("CAN ID:"))
        self.can_id_filter = QLineEdit()
        self.can_id_filter.setPlaceholderText("e.g. 0x100")
        self.can_id_filter.textChanged.connect(self.apply_traffic_filters)
        filter_row.addWidget(self.can_id_filter)
        filter_row.addWidget(QLabel("Status:"))
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All", "NORMAL", "SUSPICIOUS"])
        self.status_filter.currentTextChanged.connect(self.apply_traffic_filters)
        filter_row.addWidget(self.status_filter)
        self.export_traffic_button = QPushButton("Export Filtered Traffic CSV")
        self.export_traffic_button.clicked.connect(self.export_filtered_traffic)
        filter_row.addWidget(self.export_traffic_button)
        traffic_layout.addLayout(filter_row)
        self.traffic_table = QTableWidget(0, 4)
        self.traffic_table.setHorizontalHeaderLabels(["Timestamp", "CAN ID", "Payload", "Status"])
        self.traffic_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.traffic_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.traffic_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.traffic_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.traffic_table.setAlternatingRowColors(True)
        self.traffic_table.setEditTriggers(QTableWidget.NoEditTriggers)
        traffic_layout.addWidget(self.traffic_table)
        self.tabs.addTab(traffic_tab, "CAN Traffic")
        # Separate alert history tab.
        alert_tab = QWidget()
        alert_layout = QVBoxLayout(alert_tab)
        alert_controls = QHBoxLayout()
        alert_controls.addWidget(QLabel("Severity:"))
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
        self.severity_filter.currentTextChanged.connect(self.refresh_alert_table)
        alert_controls.addWidget(self.severity_filter)
        alert_controls.addWidget(QLabel("Reason contains:"))
        self.reason_filter = QLineEdit()
        self.reason_filter.setPlaceholderText("Search alert reason")
        self.reason_filter.textChanged.connect(self.refresh_alert_table)
        alert_controls.addWidget(self.reason_filter)
        self.export_alerts_button = QPushButton("Export Alert History CSV")
        self.export_alerts_button.setObjectName("primaryButton")
        self.export_alerts_button.clicked.connect(self.export_alert_history)
        alert_controls.addWidget(self.export_alerts_button)
        alert_layout.addLayout(alert_controls)
        self.alert_table = QTableWidget(0, 5)
        self.alert_table.setHorizontalHeaderLabels(
            ["Timestamp", "CAN ID", "Severity", "Reason", "Payload"]
        )
        self.alert_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.alert_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.alert_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.alert_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.alert_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.alert_table.setAlternatingRowColors(True)
        self.alert_table.setEditTriggers(QTableWidget.NoEditTriggers)
        alert_layout.addWidget(self.alert_table)
        self.tabs.addTab(alert_tab, "Alert History")
        self.demo_note = QLabel(
            "Demo only: generated CAN traffic is simulated. Suspicious status is assigned by demonstration logic, "
            "not by a trained ML model or a real vehicle connection."
        )
        self.demo_note.setObjectName("note")
        self.demo_note.setWordWrap(True)
        outer.addWidget(self.demo_note)
        self.setStyleSheet("""
            QMainWindow, QWidget { background: #101722; color: #e8eef7; font-family: Segoe UI; font-size: 10pt; }
            QLabel#mainTitle { font-size: 22pt; font-weight: 700; color: #f4f7fb; }
            QLabel#subtitle, QLabel#note { color: #9fb0c5; }
            QLabel#statusStopped { color: #ff7777; font-weight: 700; padding: 8px 12px; }
            QLabel#statusRunning { color: #5ce0a0; font-weight: 700; padding: 8px 12px; }
            QFrame#summaryCard { background: #192536; border: 1px solid #2b3b51; border-radius: 10px; }
            QLabel#cardLabel { color: #a8bad0; font-size: 9pt; font-weight: 600; }
            QLabel#cardValue { color: #ffffff; font-size: 20pt; font-weight: 700; }
            QPushButton { background: #26364b; color: #f4f7fb; border: 1px solid #3a4e68; border-radius: 6px; padding: 9px 12px; }
            QPushButton:hover { background: #324761; }
            QPushButton#primaryButton { background: #1976d2; border-color: #1976d2; }
            QPushButton#primaryButton:hover { background: #2587e7; }
            QPushButton#dangerButton { background: #782f3b; border-color: #9a3d4c; }
            QLineEdit, QComboBox { background: #172333; color: #e8eef7; border: 1px solid #34475e; border-radius: 5px; padding: 7px; }
            QTableWidget { background: #131d2a; alternate-background-color: #192638; gridline-color: #2a3b50; border: 1px solid #2a3b50; }
            QHeaderView::section { background: #223249; color: #e8eef7; padding: 8px; border: none; font-weight: 600; }
            QTabWidget::pane { border: 1px solid #2a3b50; border-radius: 6px; }
            QTabBar::tab { background: #1a2738; color: #aebdd0; padding: 10px 18px; border-top-left-radius: 5px; border-top-right-radius: 5px; }
            QTabBar::tab:selected { background: #263c56; color: white; }
        """)
    def make_card(self, label_text):
        card = QFrame()
        card.setObjectName("summaryCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 12, 14, 12)
        label = QLabel(label_text)
        label.setObjectName("cardLabel")
        value = QLabel("0")
        value.setObjectName("cardValue")
        value.setWordWrap(True)
        layout.addWidget(label)
        layout.addWidget(value)
        return card, value
    def start_monitoring(self):
        if not self.monitoring:
            self.monitoring = True
            self.status_label.setText("● RUNNING")
            self.status_label.setObjectName("statusRunning")
            self.status_label.style().unpolish(self.status_label)
            self.status_label.style().polish(self.status_label)
            self.timer.start(1000)
    def stop_monitoring(self):
        self.monitoring = False
        self.timer.stop()
        self.status_label.setText("● STOPPED")
        self.status_label.setObjectName("statusStopped")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)
    def generate_can_message(self):
        """Generate sample CAN traffic for dashboard demonstration only."""
        self.message_count += 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Sample payloads for recognizable demo ECU message IDs.
        # These are illustrative values, not verified vehicle encodings.
        normal_profiles = {
            "0x100": ["0C 80 00 64 00 00 00 00", "0C A0 00 64 00 00 00 00"],
            "0x101": ["00 32 00 00 00 00 00 00", "00 3C 00 00 00 00 00 00"],
            "0x120": ["19 28 2A 00 00 00 00 00", "1A 29 2B 00 00 00 00 00"],
            "0x200": ["01 00 00 00 00 00 00 00", "02 00 00 00 00 00 00 00"],
            "0x321": ["10 20 30 40 50 60 70 80", "11 21 31 41 51 61 71 81"],
            "0x450": ["00 01 02 03 04 05 06 07", "01 02 03 04 05 06 07 08"],
        }
        # Demo rule: every seventh message is marked suspicious.
        # This is simulated behavior, not a trained ML detection result.
        is_suspicious = self.message_count % 7 == 0
        if is_suspicious:
            can_id = "0x666"
            payload = " ".join(
                f"{random.randint(0, 255):02X}" for _ in range(8)
            )
            status = "SUSPICIOUS"
        else:
            can_id = random.choice(list(normal_profiles.keys()))
            payload = random.choice(normal_profiles[can_id])
            status = "NORMAL"
        record = {
            "timestamp": timestamp,
            "can_id": can_id,
            "payload": payload,
            "status": status,
        }
        self.traffic_records.append(record)
        if is_suspicious:
            self.create_alert(record)
        self.apply_traffic_filters()
        self.update_summary()
    def create_alert(self, traffic_record):
        # Cycle through levels so the UI can demonstrate all severity indicators.
        # This is illustrative logic, not a validated security classifier.
        severity_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        severity = severity_levels[len(self.alert_history) % len(severity_levels)]
        reason_by_severity = {
            "LOW": "Demo rule: unusual message flagged for review",
            "MEDIUM": "Demo rule: repeated suspicious-traffic pattern",
            "HIGH": "Demo rule: suspicious CAN ID and payload pattern",
            "CRITICAL": "Demo rule: simulated critical intrusion event",
        }
        alert = {
            "timestamp": traffic_record["timestamp"],
            "can_id": traffic_record["can_id"],
            "severity": severity,
            "reason": reason_by_severity[severity],
            "payload": traffic_record["payload"],
        }
        self.alert_history.append(alert)
        self.refresh_alert_table()
    def get_filtered_traffic_records(self):
        """Return all stored traffic records matching the active traffic filters."""
        can_query = self.can_id_filter.text().strip().lower()
        status_query = self.status_filter.currentText()
        return [
            record for record in self.traffic_records
            if can_query in record["can_id"].lower()
            and (status_query == "All" or record["status"] == status_query)
        ]
    def get_filtered_alert_records(self):
        """Return all stored alerts matching the active alert filters."""
        severity_query = self.severity_filter.currentText()
        reason_query = self.reason_filter.text().strip().lower()
        return [
            alert for alert in self.alert_history
            if (severity_query == "All" or alert["severity"] == severity_query)
            and reason_query in alert["reason"].lower()
        ]
    def apply_traffic_filters(self):
        # Keep the UI responsive by displaying at most the latest 200 matching rows.
        visible = self.get_filtered_traffic_records()[-200:]
        self.traffic_table.setRowCount(0)
        for record in visible:
            row = self.traffic_table.rowCount()
            self.traffic_table.insertRow(row)
            values = [record["timestamp"], record["can_id"], record["payload"], record["status"]]
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if col == 3 and value == "SUSPICIOUS":
                    item.setForeground(Qt.red)
                self.traffic_table.setItem(row, col, item)
    def refresh_alert_table(self):
        filtered = self.get_filtered_alert_records()[-200:]
        self.alert_table.setRowCount(0)
        for alert in filtered:
            row = self.alert_table.rowCount()
            self.alert_table.insertRow(row)
            values = [alert["timestamp"], alert["can_id"], alert["severity"], alert["reason"], alert["payload"]]
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if col == 2:
                    foreground, background = self.SEVERITY_COLORS.get(
                        value, ("#e8eef7", "#26364b")
                    )
                    item.setForeground(QColor(foreground))
                    item.setBackground(QColor(background))
                    font = item.font()
                    font.setBold(True)
                    item.setFont(font)
                self.alert_table.setItem(row, col, item)
    def _write_csv_file(self, path, headers, rows):
        """Write CSV rows safely and show a consistent success/error message."""
        path = self._append_csv_extension(path)
        try:
            self._write_csv(path, headers, rows)
        except (OSError, csv.Error, UnicodeError) as exc:
            QMessageBox.critical(self, "Export failed", f"Could not write CSV file:\n{exc}")
            return False
        QMessageBox.information(self, "Export successful", f"CSV exported successfully: {path}")
        return True
    def export_filtered_traffic(self):
        filtered = self.get_filtered_traffic_records()
        if not filtered:
            QMessageBox.information(self, "No traffic", "There are no traffic records matching the current filters.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Filtered Traffic", "can_traffic.csv", "CSV Files (*.csv)"
        )
        if not path:
            return
        rows = ([r["timestamp"], r["can_id"], r["payload"], r["status"]] for r in filtered)
        self._write_csv_file(path, ["Timestamp", "CAN ID", "Payload", "Status"], rows)
    def export_alert_history(self):
        if not self.alert_history:
            QMessageBox.information(self, "No alerts", "No alert history is available to export.")
            return
        filtered = self.get_filtered_alert_records()
        if not filtered:
            QMessageBox.information(self, "No matching alerts", "No alert records match the current alert filters.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Alert History", "can_alert_history.csv", "CSV Files (*.csv)"
        )
        if not path:
            return
        rows = ([a["timestamp"], a["can_id"], a["severity"], a["reason"], a["payload"]]
                for a in filtered)
        self._write_csv_file(
            path, ["Timestamp", "CAN ID", "Severity", "Reason", "Payload"], rows
        )
    def clear_traffic_display(self):
        # Intentionally clears only the table, not stored records/history.
        self.traffic_table.setRowCount(0)
        QMessageBox.information(
            self, "Display cleared",
            "The visible traffic table was cleared. Stored traffic and alert history are preserved for CSV export."
        )
    def clear_all_session_data(self):
        answer = QMessageBox.question(
            self, "Clear all session data",
            "This permanently removes traffic and alert history from this running session. Continue?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if answer != QMessageBox.Yes:
            return
        self.traffic_records.clear()
        self.alert_history.clear()
        self.message_count = 0
        self.alert_count = 0
        self.traffic_table.setRowCount(0)
        self.alert_table.setRowCount(0)
        self.can_id_filter.clear()
        self.status_filter.setCurrentText("All")
        self.severity_filter.setCurrentText("All")
        self.reason_filter.clear()
        self.update_summary()
    def update_summary(self):
        total = len(self.traffic_records)
        alerts = len(self.alert_history)
        self.total_value.setText(str(total))
        self.alert_value.setText(str(alerts))
        self.normal_value.setText(str(sum(1 for r in self.traffic_records if r["status"] == "NORMAL")))
        latest_severity = self.alert_history[-1]["severity"] if self.alert_history else "None"
        self.threat_value.setText(latest_severity)
        if latest_severity in self.SEVERITY_COLORS:
            foreground, _ = self.SEVERITY_COLORS[latest_severity]
            self.threat_value.setStyleSheet(f"color: {foreground}; font-weight: 700;")
        else:
            self.threat_value.setStyleSheet("color: #ffffff; font-weight: 700;")
        self.alert_count = alerts
def main():
    app = QApplication(sys.argv)
    window = CanSentinelDashboard()
    window.show()
    sys.exit(app.exec_())
if __name__ == "__main__":
    main()
