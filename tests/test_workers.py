"""Tests for the live monitoring worker. Requires the project's PyQt5 dependency."""
import os
import unittest

try:
    from integration.workers import MonitoringWorker
    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False


@unittest.skipUnless(PYQT_AVAILABLE, "PyQt5 is required to test QThread workers")
class MonitoringWorkerTests(unittest.TestCase):
    def test_rejects_demo_as_live_worker_transport(self):
        worker = MonitoringWorker("demo")
        with self.assertRaises(ValueError):
            worker._create_sniffer()

    def test_rejects_unknown_detection_transport(self):
        worker = MonitoringWorker("file", "unknown")
        with self.assertRaises(ValueError):
            worker._create_detector()

    def test_file_source_requires_path(self):
        previous = os.environ.pop("CAN_SENTINEL_SNIFFER_FILE", None)
        try:
            worker = MonitoringWorker("file")
            with self.assertRaises(ValueError):
                worker._create_sniffer()
        finally:
            if previous is not None:
                os.environ["CAN_SENTINEL_SNIFFER_FILE"] = previous

    def test_stop_sets_worker_stop_event(self):
        worker = MonitoringWorker("file")
        self.assertFalse(worker._stop_event.is_set())
        worker.stop()
        self.assertTrue(worker._stop_event.is_set())


if __name__ == "__main__":
    unittest.main()
