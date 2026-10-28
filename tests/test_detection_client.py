import json
import queue
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from integration.detection_client import (
    DetectionClientError, JsonlFileDetectionClient, QueueDetectionClient,
    TcpJsonlDetectionClient,
)

SAMPLE = {
    "timestamp": "2026-10-29T00:00:00.015Z", "can_id": "0x666",
    "severity": "HIGH", "reason": "Abnormal message frequency",
    "payload": "DE AD BE EF",
}


class DetectionClientTests(unittest.TestCase):
    def test_queue_normalizes_detection(self):
        client = QueueDetectionClient()
        client.submit(SAMPLE)
        result = client.poll()
        self.assertEqual(result[0]["can_id"], "0X666")
        self.assertEqual(result[0]["severity"], "HIGH")

    def test_queue_skips_malformed_and_continues(self):
        client = QueueDetectionClient()
        client.submit({"can_id": "0x100"})
        client.submit(SAMPLE)
        self.assertEqual(len(client.poll()), 1)
        self.assertEqual(len(client.errors), 1)

    def test_queue_respects_limit(self):
        client = QueueDetectionClient()
        client.submit(SAMPLE)
        client.submit(SAMPLE)
        self.assertEqual(len(client.poll(max_messages=1)), 1)

    def test_file_reads_complete_jsonl_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "alerts.jsonl"
            path.write_text(json.dumps(SAMPLE) + "\n", encoding="utf-8")
            client = JsonlFileDetectionClient(path, start_at_end=False)
            self.assertEqual(len(client.poll()), 1)

    def test_file_waits_for_newline(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "alerts.jsonl"
            path.write_text(json.dumps(SAMPLE), encoding="utf-8")
            client = JsonlFileDetectionClient(path, start_at_end=False)
            self.assertEqual(client.poll(), [])
            with path.open("a", encoding="utf-8") as stream:
                stream.write("\n")
            self.assertEqual(len(client.poll()), 1)

    def test_file_skips_bad_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "alerts.jsonl"
            path.write_text("not-json\n" + json.dumps(SAMPLE) + "\n", encoding="utf-8")
            client = JsonlFileDetectionClient(path, start_at_end=False)
            self.assertEqual(len(client.poll()), 1)
            self.assertEqual(len(client.errors), 1)

    def test_tcp_receives_jsonl_detection(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        def serve():
            conn, _ = listener.accept()
            with conn:
                conn.sendall((json.dumps(SAMPLE) + "\n").encode())
            listener.close()
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        client = TcpJsonlDetectionClient(port=port)
        results = []
        for _ in range(30):
            results.extend(client.poll())
            if results:
                break
            threading.Event().wait(0.01)
        client.close()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["reason"], SAMPLE["reason"])

    def test_tcp_connection_error_is_clear(self):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        with self.assertRaises(DetectionClientError):
            TcpJsonlDetectionClient(port=port, connect_timeout=0.1)


if __name__ == "__main__":
    unittest.main()
