"""Qt worker that polls CAN sniffer and detection clients off the GUI thread."""
import os
import threading
import time

from PyQt5.QtCore import QThread, pyqtSignal

from integration.sniffer_client import JsonlFileSnifferClient, TcpJsonlSnifferClient
from integration.detection_client import JsonlFileDetectionClient, TcpJsonlDetectionClient


class MonitoringWorker(QThread):
    """Owns live clients in a QThread and emits plain Python records to the UI."""
    traffic_received = pyqtSignal(list)
    detections_received = pyqtSignal(list)
    issue_reported = pyqtSignal(str)
    connection_state = pyqtSignal(str)

    def __init__(self, input_mode, detection_mode="off", poll_interval=0.05, parent=None):
        super().__init__(parent)
        self.input_mode = str(input_mode).lower()
        self.detection_mode = str(detection_mode).lower()
        self.poll_interval = max(0.01, float(poll_interval))
        self._stop_event = threading.Event()
        self._sniffer = None
        self._detector = None

    def stop(self):
        self._stop_event.set()

    def _create_sniffer(self):
        if self.input_mode == "file":
            path = os.environ.get("CAN_SENTINEL_SNIFFER_FILE", "").strip()
            if not path:
                raise ValueError("Set CAN_SENTINEL_SNIFFER_FILE to the sniffer JSONL output path.")
            from_start = os.environ.get("CAN_SENTINEL_SNIFFER_FROM_START", "0") == "1"
            return JsonlFileSnifferClient(path, start_at_end=not from_start)
        if self.input_mode == "tcp":
            return TcpJsonlSnifferClient(
                os.environ.get("CAN_SENTINEL_SNIFFER_HOST", "127.0.0.1"),
                int(os.environ.get("CAN_SENTINEL_SNIFFER_PORT", "8765")),
            )
        raise ValueError("Live worker input mode must be file or tcp.")

    def _create_detector(self):
        if self.detection_mode in {"off", "demo"}:
            return None
        if self.detection_mode == "file":
            path = os.environ.get("CAN_SENTINEL_DETECTION_FILE", "").strip()
            if not path:
                raise ValueError("Set CAN_SENTINEL_DETECTION_FILE to the detector JSONL output path.")
            from_start = os.environ.get("CAN_SENTINEL_DETECTION_FROM_START", "0") == "1"
            return JsonlFileDetectionClient(path, start_at_end=not from_start)
        if self.detection_mode == "tcp":
            return TcpJsonlDetectionClient(
                os.environ.get("CAN_SENTINEL_DETECTION_HOST", "127.0.0.1"),
                int(os.environ.get("CAN_SENTINEL_DETECTION_PORT", "8766")),
            )
        raise ValueError("CAN_SENTINEL_DETECTION_SOURCE must be off, file, or tcp.")

    def run(self):
        try:
            # Client construction (including TCP connect) happens in this worker thread.
            self._sniffer = self._create_sniffer()
            self._detector = self._create_detector()
            self.connection_state.emit("connected")
            while not self._stop_event.is_set():
                try:
                    traffic = self._sniffer.poll(max_messages=250)
                    if traffic:
                        self.traffic_received.emit(traffic)
                    if self._detector is not None:
                        detections = self._detector.poll(max_messages=250)
                        if detections:
                            self.detections_received.emit(detections)
                    for client, label in ((self._sniffer, "Sniffer"), (self._detector, "Detector")):
                        if client is not None:
                            for issue in getattr(client, "errors", []):
                                self.issue_reported.emit(f"{label}: {issue}")
                            # A closed TCP stream cannot recover without reconnecting.
                            if isinstance(client, (TcpJsonlSnifferClient, TcpJsonlDetectionClient)) and client.socket is None:
                                self.issue_reported.emit(f"{label} TCP stream stopped; monitoring worker is shutting down.")
                                self.connection_state.emit("error")
                                self._stop_event.set()
                                break
                except Exception as exc:
                    self.issue_reported.emit(f"Monitoring read error: {exc}")
                    # A broken stream should not spin at 100% CPU or freeze the GUI.
                    self._stop_event.wait(self.poll_interval * 4)
                    if self._stop_event.is_set():
                        break
                self._stop_event.wait(self.poll_interval)
        except Exception as exc:
            self.issue_reported.emit(str(exc))
            self.connection_state.emit("error")
        finally:
            for client in (self._sniffer, self._detector):
                if client is not None:
                    try:
                        client.close()
                    except Exception as exc:
                        self.issue_reported.emit(f"Error closing monitoring client: {exc}")
            self._sniffer = self._detector = None
            self.connection_state.emit("stopped")
