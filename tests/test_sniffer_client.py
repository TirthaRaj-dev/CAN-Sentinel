import json
import queue
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from integration.sniffer_client import (
    JsonlFileSnifferClient,
    QueueSnifferClient,
    SnifferClientError,
    TcpJsonlSnifferClient,
)


class QueueSnifferClientTests(unittest.TestCase):
    def test_normalizes_queued_messages(self):
        client = QueueSnifferClient()
        client.submit({"timestamp": "t1", "can_id": "0x100", "payload": "aa bb"})
        self.assertEqual(client.poll(), [{
            "timestamp": "t1", "can_id": "0X100", "payload": "AA BB", "status": "NORMAL"
        }])

    def test_skips_malformed_queue_items_without_crashing(self):
        client = QueueSnifferClient()
        client.submit(None)
        client.submit({"can_id": "0x100", "payload": "00", "status": "BROKEN"})
        client.submit({"can_id": "0x101", "payload": "01"})
        self.assertEqual(len(client.poll()), 1)
        self.assertEqual(len(client.errors), 2)

    def test_respects_poll_limit(self):
        client = QueueSnifferClient()
        for i in range(3):
            client.submit({"can_id": hex(0x100 + i), "payload": "00"})
        self.assertEqual(len(client.poll(max_messages=2)), 2)
        self.assertEqual(len(client.poll(max_messages=2)), 1)


class JsonlFileSnifferClientTests(unittest.TestCase):
    def test_reads_appended_jsonl_records(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sniffer.jsonl"
            path.write_text("", encoding="utf-8")
            client = JsonlFileSnifferClient(path)
            with path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({"timestamp": "t1", "can_id": "0x100", "payload": "aa"}) + "\n")
            records = client.poll()
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["can_id"], "0X100")

    def test_ignores_incomplete_line_until_newline_arrives(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sniffer.jsonl"
            path.write_text("", encoding="utf-8")
            client = JsonlFileSnifferClient(path)
            raw = json.dumps({"can_id": "0x100", "payload": "aa"})
            path.write_text(raw, encoding="utf-8")
            self.assertEqual(client.poll(), [])
            with path.open("a", encoding="utf-8") as stream:
                stream.write("\n")
            self.assertEqual(len(client.poll()), 1)

    def test_skips_bad_json_and_continues(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sniffer.jsonl"
            path.write_text("", encoding="utf-8")
            client = JsonlFileSnifferClient(path)
            with path.open("a", encoding="utf-8") as stream:
                stream.write("not-json\n")
                stream.write(json.dumps({"can_id": "0x100", "payload": "aa"}) + "\n")
            self.assertEqual(len(client.poll()), 1)
            self.assertEqual(len(client.errors), 1)

    def test_starts_at_end_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sniffer.jsonl"
            path.write_text(json.dumps({"can_id": "0x100", "payload": "aa"}) + "\n", encoding="utf-8")
            client = JsonlFileSnifferClient(path)
            self.assertEqual(client.poll(), [])


class TcpJsonlSnifferClientTests(unittest.TestCase):
    def test_reports_unavailable_server_cleanly(self):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        with self.assertRaises(SnifferClientError):
            TcpJsonlSnifferClient("127.0.0.1", port, connect_timeout=0.1)

    def test_receives_jsonl_message(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        def send_one():
            conn, _ = server.accept()
            with conn:
                conn.sendall((json.dumps({"timestamp": "t1", "can_id": "0x100", "payload": "aa"}) + "\n").encode())
            server.close()
        thread = threading.Thread(target=send_one, daemon=True)
        thread.start()
        client = TcpJsonlSnifferClient("127.0.0.1", port)
        records = []
        for _ in range(20):
            records = client.poll()
            if records:
                break
            threading.Event().wait(0.01)
        client.close()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["payload"], "AA")


if __name__ == "__main__":
    unittest.main()
