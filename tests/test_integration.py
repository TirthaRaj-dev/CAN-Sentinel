"""End-to-end checks for the file-based sniffer and detector interface.

These tests validate the agreed JSONL contracts and client normalization. They do
not claim that Member 2/3's live modules or the GUI were exercised.
"""
import json
import os
import tempfile
import unittest

from integration.sniffer_client import JsonlFileSnifferClient
from integration.detection_client import JsonlFileDetectionClient


class IntegratedPrototypeTests(unittest.TestCase):
    def test_sniffer_and_detector_records_can_be_consumed_together(self):
        with tempfile.TemporaryDirectory() as folder:
            traffic_path = os.path.join(folder, "traffic.jsonl")
            alert_path = os.path.join(folder, "alerts.jsonl")
            with open(traffic_path, "w", encoding="utf-8") as stream:
                stream.write(json.dumps({
                    "timestamp": "2026-10-31T10:00:00Z",
                    "can_id": "0x123", "payload": "AA BB CC DD", "status": "NORMAL"
                }) + "\n")
            with open(alert_path, "w", encoding="utf-8") as stream:
                stream.write(json.dumps({
                    "timestamp": "2026-10-31T10:00:01Z",
                    "can_id": "0x123", "severity": "HIGH",
                    "reason": "Abnormal message frequency", "payload": "AA BB CC DD"
                }) + "\n")

            sniffer = JsonlFileSnifferClient(traffic_path, start_at_end=False)
            detector = JsonlFileDetectionClient(alert_path, start_at_end=False)
            try:
                traffic = sniffer.poll(max_messages=20)
                alerts = detector.poll(max_messages=20)
            finally:
                sniffer.close()
                detector.close()

            self.assertEqual(len(traffic), 1)
            self.assertEqual(len(alerts), 1)
            self.assertEqual(traffic[0]["can_id"], alerts[0]["can_id"])
            self.assertEqual(traffic[0]["payload"], alerts[0]["payload"])
            self.assertEqual(alerts[0]["severity"], "HIGH")
            self.assertIn("timestamp", alerts[0])
            self.assertIn("reason", alerts[0])

    def test_malformed_record_does_not_prevent_following_valid_record(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "alerts.jsonl")
            with open(path, "w", encoding="utf-8") as stream:
                stream.write("{not-json}\n")
                stream.write(json.dumps({
                    "timestamp": "2026-10-31T10:00:01Z",
                    "can_id": "0x456", "severity": "MEDIUM", "reason": "Test anomaly"
                }) + "\n")
            client = JsonlFileDetectionClient(path, start_at_end=False)
            try:
                alerts = client.poll(max_messages=20)
                self.assertEqual(len(alerts), 1)
                self.assertEqual(alerts[0]["can_id"], "0X456")
                self.assertTrue(client.errors)
            finally:
                client.close()

    def test_clients_wait_for_complete_newline_delimited_records(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "traffic.jsonl")
            with open(path, "w", encoding="utf-8") as stream:
                stream.write('{"timestamp":"t","can_id":"0x1","payload":"00","status":"NORMAL"}')
            client = JsonlFileSnifferClient(path, start_at_end=False)
            try:
                self.assertEqual(client.poll(), [])
                with open(path, "a", encoding="utf-8") as stream:
                    stream.write("\n")
                self.assertEqual(len(client.poll()), 1)
            finally:
                client.close()


if __name__ == "__main__":
    unittest.main()
