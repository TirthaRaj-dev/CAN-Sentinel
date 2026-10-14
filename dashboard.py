import sys
import csv
import random
from datetime import datetime

from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QHBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QTextEdit,
    QLineEdit,
    QComboBox,
    QFileDialog,
    QMessageBox,
)


class CanSentinelDashboard(QMainWindow):
    """CAN-Sentinel demo dashboard using simulated CAN traffic."""

    def __init__(self):
        super().__init__()

        self.setWindowTitle("CAN-Sentinel | ECU Intrusion Detection")
        self.resize(1150, 800)
        self.setMinimumSize(900, 650)

        self.message_count = 0
        self.alert_count = 0

        # Keep the traffic records separately from the visible table.
        # Filters change the table view without deleting the stored records.
        self.traffic_records = []

        # Monitoring timer
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.generate_message)

        # Main widget and layout
        central = QWidget()
        self.setCentralWidget(central)

        layout = QVBoxLayout(central)
        layout.setContentsMargins(22, 18, 22, 18)
        layout.setSpacing(12)

        # Header
        title = QLabel("CAN-SENTINEL")
        title.setObjectName("title")
        layout.addWidget(title)

        subtitle = QLabel("AUTOMOTIVE ECU INTRUSION DETECTION SYSTEM")
        subtitle.setObjectName("subtitle")
        layout.addWidget(subtitle)

        # Monitoring status
        status_row = QHBoxLayout()
        status_heading = QLabel("MONITORING STATUS")
        status_heading.setObjectName("sectionHeading")

        self.monitoring_status = QLabel("● STOPPED")
        self.monitoring_status.setObjectName("stoppedStatus")

        status_row.addWidget(status_heading)
        status_row.addStretch()
        status_row.addWidget(self.monitoring_status)
        layout.addLayout(status_row)

        # Summary cards
        summary = QHBoxLayout()
        summary.setSpacing(12)

        self.total_label = QLabel("Total Messages\n0")
        self.alert_label = QLabel("Intrusion Alerts\n0")
        self.threat_label = QLabel("Threat Level\nLOW")

        for label in (
            self.total_label,
            self.alert_label,
            self.threat_label,
        ):
            label.setObjectName("summaryCard")
            label.setAlignment(Qt.AlignCenter)
            label.setMinimumHeight(70)
            summary.addWidget(label)

        self.threat_label.setObjectName("lowThreat")
        layout.addLayout(summary)

        # Traffic section
        heading = QLabel("CAN TRAFFIC MONITOR")
        heading.setObjectName("sectionHeading")
        layout.addWidget(heading)

        # Day 4: traffic filters
        filter_row = QHBoxLayout()
        filter_row.setSpacing(10)

        filter_label = QLabel("Filter CAN ID:")
        self.can_id_filter = QLineEdit()
        self.can_id_filter.setPlaceholderText("e.g. 0x100 (leave blank for all)")
        self.can_id_filter.setClearButtonEnabled(True)
        self.can_id_filter.textChanged.connect(self.apply_filters)

        status_filter_label = QLabel("Status:")
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All", "NORMAL", "SUSPICIOUS"])
        self.status_filter.currentTextChanged.connect(self.apply_filters)

        self.export_button = QPushButton("Export Filtered CSV")
        self.export_button.setObjectName("exportButton")
        self.export_button.clicked.connect(self.export_traffic_csv)

        filter_row.addWidget(filter_label)
        filter_row.addWidget(self.can_id_filter, 2)
        filter_row.addWidget(status_filter_label)
        filter_row.addWidget(self.status_filter, 1)
        filter_row.addWidget(self.export_button)
        layout.addLayout(filter_row)

        self.filter_summary = QLabel("Showing 0 of 0 retained records")
        self.filter_summary.setObjectName("filterSummary")
        layout.addWidget(self.filter_summary)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(
            ["Timestamp", "CAN ID", "Payload", "Status"]
        )
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setMinimumHeight(220)
        layout.addWidget(self.table, 1)

        # Alert section
        alert_heading = QLabel("INTRUSION ALERTS")
        alert_heading.setObjectName("sectionHeading")
        layout.addWidget(alert_heading)

        self.alert_box = QTextEdit()
        self.alert_box.setReadOnly(True)
        self.alert_box.setPlaceholderText(
            "Suspicious message alerts will appear here..."
        )
        self.alert_box.setMaximumHeight(100)
        self.alert_box.document().setMaximumBlockCount(100)
        layout.addWidget(self.alert_box)

        # Control buttons
        buttons = QHBoxLayout()
        buttons.setSpacing(12)

        self.start_button = QPushButton("Start Monitoring")
        self.start_button.setObjectName("startButton")
        self.start_button.clicked.connect(self.start_monitoring)

        self.stop_button = QPushButton("Stop Monitoring")
        self.stop_button.setObjectName("stopButton")
        self.stop_button.clicked.connect(self.stop_monitoring)
        self.stop_button.setEnabled(False)

        self.clear_button = QPushButton("Clear Data")
        self.clear_button.setObjectName("clearButton")
        self.clear_button.clicked.connect(self.clear_data)

        buttons.addWidget(self.start_button)
        buttons.addWidget(self.stop_button)
        buttons.addWidget(self.clear_button)
        layout.addLayout(buttons)

        footer = QLabel(
            "DEMO MODE — Simulated CAN traffic; "
            "not connected to a real vehicle or ML model."
        )
        footer.setObjectName("footer")
        footer.setAlignment(Qt.AlignCenter)
        layout.addWidget(footer)

        # Dashboard styling
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #101827;
                color: #E5E7EB;
                font-family: "Segoe UI";
                font-size: 13px;
            }
            QLabel#title {
                color: #60A5FA;
                font-size: 28px;
                font-weight: bold;
            }
            QLabel#subtitle {
                color: #9CA3AF;
                font-size: 12px;
                padding-bottom: 4px;
            }
            QLabel#sectionHeading {
                color: #93C5FD;
                font-size: 15px;
                font-weight: bold;
                padding-top: 3px;
            }
            QLabel#summaryCard {
                background-color: #1B2638;
                border: 1px solid #344256;
                border-radius: 8px;
                padding: 10px;
                font-size: 15px;
                font-weight: bold;
            }
            QLabel#stoppedStatus {
                color: #F87171;
                font-weight: bold;
                padding: 6px 10px;
                background-color: #351F2A;
                border-radius: 6px;
            }
            QLabel#runningStatus {
                color: #4ADE80;
                font-weight: bold;
                padding: 6px 10px;
                background-color: #15382C;
                border-radius: 6px;
            }
            QLabel#lowThreat {
                color: #4ADE80;
                background-color: #15382C;
                border: 1px solid #28664A;
                border-radius: 8px;
                padding: 10px;
                font-weight: bold;
            }
            QLabel#highThreat {
                color: #F87171;
                background-color: #351F2A;
                border: 1px solid #803646;
                border-radius: 8px;
                padding: 10px;
                font-weight: bold;
            }
            QLabel#filterSummary {
                color: #9CA3AF;
                font-size: 11px;
            }
            QLineEdit, QComboBox {
                background-color: #1B2638;
                color: #E5E7EB;
                border: 1px solid #344256;
                border-radius: 5px;
                padding: 7px;
                min-height: 20px;
            }
            QTableWidget, QTextEdit {
                background-color: #1B2638;
                alternate-background-color: #202D40;
                color: #E5E7EB;
                gridline-color: #344256;
                border: 1px solid #344256;
                border-radius: 6px;
                selection-background-color: #1D4ED8;
                selection-color: white;
            }
            QHeaderView::section {
                background-color: #26364C;
                color: #FFFFFF;
                padding: 9px;
                border: none;
                font-weight: bold;
            }
            QPushButton {
                color: white;
                padding: 9px 12px;
                border: none;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton#startButton {
                background-color: #15803D;
            }
            QPushButton#startButton:hover {
                background-color: #16A34A;
            }
            QPushButton#stopButton {
                background-color: #B91C1C;
            }
            QPushButton#stopButton:hover {
                background-color: #DC2626;
            }
            QPushButton#clearButton {
                background-color: #334155;
            }
            QPushButton#clearButton:hover {
                background-color: #475569;
            }
            QPushButton#exportButton {
                background-color: #1D4ED8;
            }
            QPushButton#exportButton:hover {
                background-color: #2563EB;
            }
            QPushButton:disabled {
                background-color: #374151;
                color: #9CA3AF;
            }
            QLabel#footer {
                color: #9CA3AF;
                font-size: 11px;
                padding-top: 3px;
            }
        """)

        self.apply_filters()

    def start_monitoring(self):
        if not self.timer.isActive():
            self.timer.start(500)
            self.monitoring_status.setText("● RUNNING")
            self.monitoring_status.setObjectName("runningStatus")
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.refresh_status_style(self.monitoring_status)

    def stop_monitoring(self):
        self.timer.stop()
        self.monitoring_status.setText("● STOPPED")
        self.monitoring_status.setObjectName("stoppedStatus")
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.refresh_status_style(self.monitoring_status)

    @staticmethod
    def refresh_status_style(widget):
        widget.style().unpolish(widget)
        widget.style().polish(widget)
        widget.update()

    def generate_message(self):
        self.message_count += 1

        normal_ids = ["0x100", "0x120", "0x200", "0x310"]
        can_id = random.choice(normal_ids)

        payload = " ".join(
            f"{random.randint(0, 255):02X}"
            for _ in range(8)
        )
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        # DEMO RULE ONLY: every seventh message is marked suspicious.
        suspicious = self.message_count % 7 == 0

        if suspicious:
            can_id = "0x666"
            status = "SUSPICIOUS"
            self.alert_count += 1
            self.alert_box.append(
                f"[{timestamp}] HIGH | DEMO ALERT | CAN ID: {can_id} | "
                f"Payload: {payload} | Reason: demonstration rule "
                "(every seventh message)."
            )
            self.threat_label.setText("Threat Level\nHIGH")
            self.threat_label.setObjectName("highThreat")
            self.refresh_status_style(self.threat_label)
        else:
            status = "NORMAL"
            self.threat_label.setText("Threat Level\nLOW")
            self.threat_label.setObjectName("lowThreat")
            self.refresh_status_style(self.threat_label)

        record = {
            "timestamp": timestamp,
            "can_id": can_id,
            "payload": payload,
            "status": status,
        }
        self.traffic_records.append(record)

        self.apply_filters()
        self.total_label.setText(f"Total Messages\n{self.message_count}")
        self.alert_label.setText(f"Intrusion Alerts\n{self.alert_count}")

    def apply_filters(self, *_):
        """Display records matching both the CAN ID and status filters."""
        can_id_query = self.can_id_filter.text().strip().casefold()
        selected_status = self.status_filter.currentText()

        matching_records = [
            record for record in self.traffic_records
            if can_id_query in record["can_id"].casefold()
            and (
                selected_status == "All"
                or record["status"] == selected_status
            )
        ]

        # Keep the interface responsive by showing at most 200 matching rows.
        visible_records = matching_records[-200:]
        self.table.setRowCount(0)

        for record in visible_records:
            row = self.table.rowCount()
            self.table.insertRow(row)
            values = [
                record["timestamp"],
                record["can_id"],
                record["payload"],
                record["status"],
            ]

            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setTextAlignment(Qt.AlignCenter)
                if record["status"] == "SUSPICIOUS":
                    item.setForeground(Qt.red)
                self.table.setItem(row, column, item)

        self.table.scrollToBottom()
        self.filter_summary.setText(
            f"Showing {len(visible_records)} of "
            f"{len(matching_records)} matching records "
            f"({len(self.traffic_records)} total retained)"
        )

    def export_traffic_csv(self):
        """Export records matching the current filters to a CSV file."""
        can_id_query = self.can_id_filter.text().strip().casefold()
        selected_status = self.status_filter.currentText()

        matching_records = [
            record for record in self.traffic_records
            if can_id_query in record["can_id"].casefold()
            and (
                selected_status == "All"
                or record["status"] == selected_status
            )
        ]

        if not matching_records:
            QMessageBox.information(
                self,
                "No traffic to export",
                "No traffic records match the current filters.",
            )
            return

        default_name = (
            "can_traffic_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".csv"
        )
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export CAN Traffic",
            default_name,
            "CSV Files (*.csv)",
        )

        if not file_path:
            return

        if not file_path.lower().endswith(".csv"):
            file_path += ".csv"

        try:
            with open(file_path, "w", newline="", encoding="utf-8-sig") as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow(["Timestamp", "CAN ID", "Payload", "Status"])
                for record in matching_records:
                    writer.writerow([
                        record["timestamp"],
                        record["can_id"],
                        record["payload"],
                        record["status"],
                    ])

            QMessageBox.information(
                self,
                "Export successful",
                f"Exported {len(matching_records)} record(s) to:\n{file_path}",
            )
        except OSError as error:
            QMessageBox.critical(
                self,
                "Export failed",
                f"Could not save the CSV file:\n{error}",
            )

    def clear_data(self):
        self.table.setRowCount(0)
        self.alert_box.clear()
        self.traffic_records.clear()

        self.message_count = 0
        self.alert_count = 0

        self.total_label.setText("Total Messages\n0")
        self.alert_label.setText("Intrusion Alerts\n0")
        self.threat_label.setText("Threat Level\nLOW")
        self.threat_label.setObjectName("lowThreat")
        self.refresh_status_style(self.threat_label)

        self.can_id_filter.clear()
        self.status_filter.setCurrentText("All")
        self.apply_filters()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CanSentinelDashboard()
    window.show()
    sys.exit(app.exec_())
