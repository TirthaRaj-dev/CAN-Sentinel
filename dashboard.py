import csv
import os
import random
import sys
from datetime import datetime

from PyQt5.QtCore import QTimer, Qt

from integration.adapter import normalize_traffic_message, normalize_detection_result
from integration.sniffer_client import (
    JsonlFileSnifferClient, SnifferClientError, TcpJsonlSnifferClient,
)
from integration.detection_client import DetectionClientError
from integration.workers import MonitoringWorker
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


class CanSentinelDashboard(QMainWindow):
    """Dashboard for demonstrating simulated CAN traffic and alert history."""

    SEVERITY_COLORS = {
        "LOW": ("#5ce0a0", "#173b32"),
        "MEDIUM": ("#f4d35e", "#443b1b"),
        "HIGH": ("#ff9f43", "#492d1c"),
        "CRITICAL": ("#ff6b6b", "#4a2028"),
    }
    TRAFFIC_COLUMNS = ["Timestamp", "CAN ID", "Payload", "Status"]
    ALERT_COLUMNS = ["Detection Timestamp", "CAN ID", "Severity", "Reason", "Payload", "Traffic Match"]
    MAX_VISIBLE_TRAFFIC_ROWS = 200
    MAX_VISIBLE_ALERT_ROWS = 200

    def __init__(self):
        super().__init__()
        self.setWindowTitle("CAN-Sentinel | Automotive ECU Intrusion Detection")
        self.resize(1280, 820)

        self.traffic_records = []
        self.alert_history = []
        self.message_count = 0
        self.alert_count = 0
        self.monitoring = False
        self.sniffer_client = None
        self.detection_client = None
        self.monitoring_worker = None
        self._seen_detection_keys = set()
        self.detection_mode = os.environ.get("CAN_SENTINEL_DETECTION_SOURCE", "off").strip().lower()
        self.input_mode = os.environ.get("CAN_SENTINEL_SOURCE", "demo").strip().lower()
        self.integration_error_count = 0

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.generate_can_message)

        self.build_ui()
        self.update_summary()
        self.apply_traffic_filters()
        self.refresh_alert_table()

    @staticmethod
    def _append_csv_extension(path):
        """Add .csv unless the selected filename already has that extension."""
        return path if path.lower().endswith(".csv") else path + ".csv"

    @staticmethod
    def _write_csv(path, columns, rows):
        """Write a CSV header and rows; return the number of data rows written."""
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
        subtitle = QLabel(
            "Automotive ECU Intrusion Detection System • Demonstration Mode"
        )
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
            "Clears visible traffic rows only; stored records remain available for export."
        )
        self.clear_display_button.clicked.connect(self.clear_traffic_display)

        self.clear_all_button = QPushButton("Clear All Session Data")
        self.clear_all_button.setObjectName("dangerButton")
        self.clear_all_button.setToolTip(
            "Permanently clears traffic and alert records from this running session."
        )
        self.clear_all_button.clicked.connect(self.clear_all_session_data)

        for button in (
            self.start_button,
            self.stop_button,
            self.clear_display_button,
            self.clear_all_button,
        ):
            controls.addWidget(button)
        controls.addStretch()
        outer.addLayout(controls)

        self.tabs = QTabWidget()
        outer.addWidget(self.tabs, 1)

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

        self.traffic_table = QTableWidget(0, len(self.TRAFFIC_COLUMNS))
        self.traffic_table.setHorizontalHeaderLabels(self.TRAFFIC_COLUMNS)
        header = self.traffic_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.traffic_table.setAlternatingRowColors(True)
        self.traffic_table.setEditTriggers(QTableWidget.NoEditTriggers)
        traffic_layout.addWidget(self.traffic_table)
        self.tabs.addTab(traffic_tab, "CAN Traffic")

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

        self.clear_alert_display_button = QPushButton("Clear Alert Display")
        self.clear_alert_display_button.setToolTip(
            "Clears visible alert rows only; stored alert history remains available for export."
        )
        self.clear_alert_display_button.clicked.connect(self.clear_alert_display)
        alert_controls.addWidget(self.clear_alert_display_button)
        alert_layout.addLayout(alert_controls)

        self.alert_table = QTableWidget(0, len(self.ALERT_COLUMNS))
        self.alert_table.setHorizontalHeaderLabels(self.ALERT_COLUMNS)
        header = self.alert_table.horizontalHeader()
        for column in (0, 1, 2):
            header.setSectionResizeMode(column, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.setSectionResizeMode(4, QHeaderView.Stretch)
        self.alert_table.setAlternatingRowColors(True)
        self.alert_table.setEditTriggers(QTableWidget.NoEditTriggers)
        alert_layout.addWidget(self.alert_table)
        self.tabs.addTab(alert_tab, "Alert History")

        self.demo_note = QLabel(
            "Demo only: generated CAN traffic is simulated. Suspicious status is "
            "assigned by demonstration logic, not by a trained ML model or a real "
            "vehicle connection."
        )
        self.demo_note.setObjectName("note")
        self.demo_note.setWordWrap(True)
        outer.addWidget(self.demo_note)

        self.setStyleSheet("""
            QMainWindow, QWidget {
                background: #101722; color: #e8eef7;
                font-family: Segoe UI; font-size: 10pt;
            }
            QLabel#mainTitle { font-size: 22pt; font-weight: 700; color: #f4f7fb; }
            QLabel#subtitle, QLabel#note { color: #9fb0c5; }
            QLabel#statusStopped { color: #ff7777; font-weight: 700; padding: 8px 12px; }
            QLabel#statusRunning { color: #5ce0a0; font-weight: 700; padding: 8px 12px; }
            QFrame#summaryCard {
                background: #192536; border: 1px solid #2b3b51; border-radius: 10px;
            }
            QLabel#cardLabel { color: #a8bad0; font-size: 9pt; font-weight: 600; }
            QLabel#cardValue { color: #ffffff; font-size: 20pt; font-weight: 700; }
            QPushButton {
                background: #26364b; color: #f4f7fb; border: 1px solid #3a4e68;
                border-radius: 6px; padding: 9px 12px;
            }
            QPushButton:hover { background: #324761; }
            QPushButton#primaryButton { background: #1976d2; border-color: #1976d2; }
            QPushButton#primaryButton:hover { background: #2587e7; }
            QPushButton#dangerButton { background: #782f3b; border-color: #9a3d4c; }
            QLineEdit, QComboBox {
                background: #172333; color: #e8eef7; border: 1px solid #34475e;
                border-radius: 5px; padding: 7px;
            }
            QTableWidget {
                background: #131d2a; alternate-background-color: #192638;
                gridline-color: #2a3b50; border: 1px solid #2a3b50;
            }
            QHeaderView::section {
                background: #223249; color: #e8eef7; padding: 8px;
                border: none; font-weight: 600;
            }
            QTabWidget::pane { border: 1px solid #2a3b50; border-radius: 6px; }
            QTabBar::tab {
                background: #1a2738; color: #aebdd0; padding: 10px 18px;
                border-top-left-radius: 5px; border-top-right-radius: 5px;
            }
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
        """Start demo timer or move live sniffer/detector reads into a QThread."""
        if self.monitoring:
            return
        self.input_mode = os.environ.get("CAN_SENTINEL_SOURCE", "demo").strip().lower()
        self.detection_mode = os.environ.get("CAN_SENTINEL_DETECTION_SOURCE", "off").strip().lower()
        if self.input_mode not in {"demo", "file", "tcp"}:
            QMessageBox.warning(self, "Unknown input source", "CAN_SENTINEL_SOURCE must be demo, file, or tcp.")
            return
        if self.detection_mode not in {"off", "demo", "file", "tcp"}:
            QMessageBox.warning(self, "Unknown detection source", "Detection source must be off, demo, file, or tcp.")
            return
        self.monitoring = True
        mode_label = {"demo": "DEMO", "file": "LIVE FILE", "tcp": "LIVE TCP"}[self.input_mode]
        self.status_label.setText(f"● STARTING · {mode_label}")
        self.status_label.setToolTip("Live reads run in a background QThread.")
        if self.input_mode == "demo":
            self.status_label.setText("● RUNNING · DEMO")
            self.timer.start(1000)
            return
        self.monitoring_worker = MonitoringWorker(self.input_mode, self.detection_mode, parent=self)
        self.monitoring_worker.traffic_received.connect(self.handle_worker_traffic)
        self.monitoring_worker.detections_received.connect(self.handle_worker_detections)
        self.monitoring_worker.issue_reported.connect(self.handle_worker_issue)
        self.monitoring_worker.connection_state.connect(self.handle_worker_state)
        self.monitoring_worker.start()

    def handle_worker_traffic(self, records):
        """Apply worker-delivered traffic on the GUI thread only."""
        if not self.monitoring:
            return
        for record in records:
            try:
                normalized = normalize_traffic_message(record)
            except (TypeError, ValueError) as exc:
                self.integration_error_count += 1
                self.status_label.setToolTip(f"Skipped invalid sniffer message: {exc}")
                continue
            self.traffic_records.append(normalized)
            self.message_count += 1
        self.apply_traffic_filters()
        self.update_summary()

    def handle_worker_detections(self, results):
        """Apply detector results on the GUI thread and suppress exact repeats."""
        if not self.monitoring:
            return
        for result in results:
            try:
                alert = normalize_detection_result(result)
            except (TypeError, ValueError) as exc:
                self.integration_error_count += 1
                self.status_label.setToolTip(f"Skipped invalid detection result: {exc}")
                continue
            fingerprint = (alert.get("timestamp", ""), alert["can_id"].upper(),
                           alert["severity"], alert["reason"], alert.get("payload", "").upper())
            if fingerprint in self._seen_detection_keys:
                continue
            self._seen_detection_keys.add(fingerprint)
            matched = self.match_detection_to_traffic(alert)
            alert["traffic_match"] = matched.get("timestamp", "No matching traffic") if matched else "No matching traffic"
            if matched:
                matched["status"] = "SUSPICIOUS"
                if not alert.get("payload"):
                    alert["payload"] = matched.get("payload", "")
            else:
                alert.setdefault("payload", "")
            self.alert_history.append(alert)
        self.refresh_alert_table()
        self.update_summary()

    def handle_worker_issue(self, message):
        self.integration_error_count += 1
        self.status_label.setToolTip(message)

    def handle_worker_state(self, state):
        if state == "connected" and self.monitoring:
            self.status_label.setText("● RUNNING · LIVE")
        elif state == "error":
            self.monitoring = False
            self.status_label.setText("● ERROR")
        elif state == "stopped" and not self.monitoring:
            self.status_label.setText("● STOPPED")

    def stop_monitoring(self):
        self.monitoring = False
        self.timer.stop()
        worker = self.monitoring_worker
        self.monitoring_worker = None
        if worker is not None and worker.isRunning():
            worker.stop()
            worker.wait(2000)
            if worker.isRunning():
                self.status_label.setToolTip("Worker is still shutting down; wait before starting again.")
                self.monitoring_worker = worker
                return
        self.status_label.setText("● STOPPED")
        self.status_label.setObjectName("statusStopped")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

    def generate_can_message(self):
        """Demo-only timer callback; live input is handled by MonitoringWorker."""
        if self.input_mode == "demo" and self.monitoring:
            self.generate_demo_message()
            self.apply_traffic_filters()
            self.update_summary()

    def match_detection_to_traffic(self, alert):
        """Match CAN ID and optional payload, preferring the most recent traffic row."""
        candidates = [r for r in reversed(self.traffic_records) if r["can_id"].upper() == alert["can_id"].upper()]
        if alert.get("payload"):
            payload_matches = [r for r in candidates if r.get("payload", "").upper() == alert["payload"].upper()]
            if payload_matches:
                return payload_matches[0]
        return candidates[0] if candidates else None

    def generate_demo_message(self):
        """Generate sample CAN traffic for dashboard demonstration only."""
        self.message_count += 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Illustrative payloads only; these are not verified vehicle encodings.
        normal_profiles = {
            "0x100": ["0C 80 00 64 00 00 00 00", "0C A0 00 64 00 00 00 00"],
            "0x101": ["00 32 00 00 00 00 00 00", "00 3C 00 00 00 00 00 00"],
            "0x120": ["19 28 2A 00 00 00 00 00", "1A 29 2B 00 00 00 00 00"],
            "0x200": ["01 00 00 00 00 00 00 00", "02 00 00 00 00 00 00 00"],
            "0x321": ["10 20 30 40 50 60 70 80", "11 21 31 41 51 61 71 81"],
            "0x450": ["00 01 02 03 04 05 06 07", "01 02 03 04 05 06 07 08"],
        }

        # Every seventh message is suspicious in this demo; this is not ML.
        is_suspicious = self.message_count % 7 == 0
        if is_suspicious:
            can_id = "0x666"
            payload = " ".join(f"{random.randint(0, 255):02X}" for _ in range(8))
            status = "SUSPICIOUS"
        else:
            can_id = random.choice(list(normal_profiles))
            payload = random.choice(normal_profiles[can_id])
            status = "NORMAL"

        # Route demo input through the same schema adapter planned for live traffic.
        record = normalize_traffic_message({
            "timestamp": timestamp,
            "can_id": can_id,
            "payload": payload,
            "status": status,
        })
        self.traffic_records.append(record)

        if is_suspicious and self.detection_mode not in {"file", "tcp"}:
            self.create_alert(record)

        self.apply_traffic_filters()
        self.update_summary()

    def create_alert(self, traffic_record):
        """Create a demonstration alert for a suspicious simulated message."""
        severity_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        severity = severity_levels[len(self.alert_history) % len(severity_levels)]
        reason_by_severity = {
            "LOW": "Demo rule: unusual message flagged for review",
            "MEDIUM": "Demo rule: repeated suspicious-traffic pattern",
            "HIGH": "Demo rule: suspicious CAN ID and payload pattern",
            "CRITICAL": "Demo rule: simulated critical intrusion event",
        }
        # Demo alert follows the same detection-result contract as Member 3 output.
        alert = normalize_detection_result({
            "timestamp": traffic_record["timestamp"],
            "can_id": traffic_record["can_id"],
            "severity": severity,
            "reason": reason_by_severity[severity],
            "payload": traffic_record["payload"],
        })
        alert["traffic_match"] = traffic_record["timestamp"]
        self.alert_history.append(alert)
        self.refresh_alert_table()

    def get_filtered_traffic_records(self):
        """Return all stored records matching the active traffic filters."""
        can_query = self.can_id_filter.text().strip().lower()
        status_query = self.status_filter.currentText()
        return [
            record for record in self.traffic_records
            if can_query in record["can_id"].lower()
            and (status_query == "All" or record["status"] == status_query)
        ]

    def get_filtered_alert_records(self):
        """Return stored alerts matching the active severity and reason filters."""
        severity_query = self.severity_filter.currentText()
        reason_query = self.reason_filter.text().strip().lower()
        return [
            alert for alert in self.alert_history
            if (severity_query == "All" or alert["severity"] == severity_query)
            and reason_query in alert["reason"].lower()
        ]

    def apply_traffic_filters(self, *_):
        # Limit only visible rows to keep the interface responsive; records remain stored.
        visible = self.get_filtered_traffic_records()[-self.MAX_VISIBLE_TRAFFIC_ROWS:]
        self.traffic_table.setRowCount(0)
        for record in visible:
            row = self.traffic_table.rowCount()
            self.traffic_table.insertRow(row)
            values = [record["timestamp"], record["can_id"], record["payload"], record["status"]]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column == 3 and value == "SUSPICIOUS":
                    item.setForeground(QColor("#ff7777"))
                self.traffic_table.setItem(row, column, item)

    def refresh_alert_table(self, *_):
        filtered = self.get_filtered_alert_records()[-self.MAX_VISIBLE_ALERT_ROWS:]
        self.alert_table.setRowCount(0)
        for alert in filtered:
            row = self.alert_table.rowCount()
            self.alert_table.insertRow(row)
            values = [
                alert["timestamp"], alert["can_id"], alert["severity"],
                alert["reason"], alert.get("payload", ""),
                alert.get("traffic_match", "Not recorded")
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column == 2:
                    foreground, background = self.SEVERITY_COLORS.get(
                        value, ("#e8eef7", "#26364b")
                    )
                    item.setForeground(QColor(foreground))
                    item.setBackground(QColor(background))
                    font = item.font()
                    font.setBold(True)
                    item.setFont(font)
                self.alert_table.setItem(row, column, item)

    def export_filtered_traffic(self):
        filtered = self.get_filtered_traffic_records()
        if not filtered:
            QMessageBox.information(
                self, "No traffic", "There are no traffic records matching the current filters."
            )
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Filtered Traffic", "can_traffic.csv", "CSV Files (*.csv)"
        )
        if path:
            rows = (
                [record["timestamp"], record["can_id"], record["payload"], record["status"]]
                for record in filtered
            )
            self._write_csv_file(path, self.TRAFFIC_COLUMNS, rows)

    def export_alert_history(self):
        if not self.alert_history:
            QMessageBox.information(
                self, "No alerts", "No alert history is available to export."
            )
            return
        filtered = self.get_filtered_alert_records()
        if not filtered:
            QMessageBox.information(
                self, "No matching alerts", "No alert records match the current alert filters."
            )
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Alert History", "can_alert_history.csv", "CSV Files (*.csv)"
        )
        if path:
            rows = (
                [alert["timestamp"], alert["can_id"], alert["severity"],
                 alert["reason"], alert.get("payload", ""),
                 alert.get("traffic_match", "Not recorded")]
                for alert in filtered
            )
            self._write_csv_file(path, self.ALERT_COLUMNS, rows)

    def _write_csv_file(self, path, headers, rows):
        """Save a CSV and report the exact number of exported records."""
        path = self._append_csv_extension(path)
        try:
            exported_count = self._write_csv(path, headers, rows)
        except (OSError, csv.Error, UnicodeError) as error:
            QMessageBox.critical(self, "Export failed", f"Could not write CSV file:\n{error}")
            return None

        QMessageBox.information(
            self, "Export successful",
            f"Exported {exported_count} record(s) to CSV successfully:\n{path}"
        )
        return exported_count

    def clear_traffic_display(self):
        """Clear visible traffic rows while retaining stored records for export."""
        self.traffic_table.setRowCount(0)
        QMessageBox.information(
            self, "Display cleared",
            "The visible traffic table was cleared. Stored traffic records remain available for filtering and CSV export."
        )

    def clear_alert_display(self):
        """Clear visible alert rows while retaining stored alert history for export."""
        self.alert_table.setRowCount(0)
        QMessageBox.information(
            self, "Alert display cleared",
            "The visible alert table was cleared. Stored alert history remains available for filtering and CSV export."
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
        self._seen_detection_keys.clear()
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
        self.normal_value.setText(
            str(sum(record["status"] == "NORMAL" for record in self.traffic_records))
        )
        latest_severity = self.alert_history[-1]["severity"] if self.alert_history else "None"
        self.threat_value.setText(latest_severity)
        if latest_severity in self.SEVERITY_COLORS:
            foreground, _ = self.SEVERITY_COLORS[latest_severity]
            self.threat_value.setStyleSheet(f"color: {foreground}; font-weight: 700;")
        else:
            self.threat_value.setStyleSheet("color: #ffffff; font-weight: 700;")
        self.alert_count = alerts


    def closeEvent(self, event):
        """Stop background monitoring before the window is destroyed."""
        self.stop_monitoring()
        if self.monitoring_worker is not None and self.monitoring_worker.isRunning():
            self.monitoring_worker.stop()
            self.monitoring_worker.wait(2000)
        event.accept()

def main():
    app = QApplication(sys.argv)
    window = CanSentinelDashboard()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()

