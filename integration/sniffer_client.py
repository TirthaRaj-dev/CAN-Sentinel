"""Small, non-blocking clients for consuming Member 2's CAN sniffer output.

Supported transports:
- QueueSnifferClient: in-process queue for integration/tests.
- JsonlFileSnifferClient: newline-delimited JSON records appended to a file.
- TcpJsonlSnifferClient: newline-delimited JSON over a TCP connection.

Each valid input is normalized using the shared adapter. Invalid records are
skipped and recorded in ``errors`` rather than crashing the dashboard.
"""
import json
import queue
import socket
from pathlib import Path

from integration.adapter import normalize_traffic_message


class SnifferClientError(RuntimeError):
    """Raised for transport configuration or connection failures."""


class QueueSnifferClient:
    """Adapter for a queue fed by another Python module in the same process."""

    def __init__(self, message_queue=None):
        self.message_queue = message_queue or queue.Queue()
        self.errors = []

    def submit(self, message):
        """Convenience method for producers/tests to enqueue a raw message."""
        self.message_queue.put(message)

    def poll(self, max_messages=100):
        records = []
        self.errors = []
        for _ in range(max(0, int(max_messages))):
            try:
                raw = self.message_queue.get_nowait()
            except queue.Empty:
                break
            try:
                records.append(normalize_traffic_message(raw))
            except (TypeError, ValueError, AttributeError) as exc:
                self.errors.append(f"Invalid queued message: {exc}")
        return records

    def close(self):
        """No external resources need closing for a queue."""


class JsonlFileSnifferClient:
    """Read newly appended newline-delimited JSON objects from a file."""

    def __init__(self, path, start_at_end=True):
        if not str(path).strip():
            raise ValueError("A sniffer JSONL file path is required")
        self.path = Path(path)
        self.offset = 0
        self.errors = []
        self.pending_lines = []
        if start_at_end and self.path.exists():
            self.offset = self.path.stat().st_size

    def poll(self, max_messages=100):
        self.errors = []
        if not self.path.exists():
            return []
        try:
            size = self.path.stat().st_size
            if size < self.offset:  # file was truncated or rotated
                self.offset = 0
                self.pending_lines.clear()
            with self.path.open("rb") as stream:
                stream.seek(self.offset)
                chunk = stream.read()
                self.offset = stream.tell()
        except OSError as exc:
            self.errors.append(f"Could not read sniffer file: {exc}")
            return []

        # Work in bytes so offsets remain correct even if a JSON string contains UTF-8.
        if chunk and not chunk.endswith(b"\n"):
            last_newline = chunk.rfind(b"\n")
            if last_newline < 0:
                complete, partial = b"", chunk
            else:
                complete, partial = chunk[:last_newline + 1], chunk[last_newline + 1:]
            self.offset -= len(partial)
        else:
            complete = chunk
        if complete:
            self.pending_lines.extend(complete.decode("utf-8", errors="replace").splitlines())

        records = []
        limit = max(0, int(max_messages))
        while self.pending_lines and len(records) < limit:
            line = self.pending_lines.pop(0)
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
                records.append(normalize_traffic_message(raw))
            except (json.JSONDecodeError, TypeError, ValueError, AttributeError) as exc:
                self.errors.append(f"Skipped malformed JSONL record: {exc}")
        return records

    def close(self):
        """Files are opened per poll, so there is no persistent handle to close."""


class TcpJsonlSnifferClient:
    """Consume newline-delimited JSON from a TCP server without blocking polls."""

    def __init__(self, host="127.0.0.1", port=8765, connect_timeout=0.5):
        self.host = str(host)
        self.port = int(port)
        self.connect_timeout = float(connect_timeout)
        self.socket = None
        self.buffer = b""
        self.errors = []
        self._connect()

    def _connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.connect_timeout)
        try:
            sock.connect((self.host, self.port))
        except OSError as exc:
            sock.close()
            raise SnifferClientError(
                f"Could not connect to sniffer at {self.host}:{self.port}: {exc}"
            ) from exc
        sock.setblocking(False)
        self.socket = sock

    def poll(self, max_messages=100):
        self.errors = []
        if self.socket is None:
            return []
        try:
            while True:
                try:
                    chunk = self.socket.recv(65536)
                except BlockingIOError:
                    break
                if not chunk:
                    self.errors.append("Sniffer TCP connection closed")
                    self.close()
                    break
                self.buffer += chunk
                if len(self.buffer) > 1_000_000 and b"\n" not in self.buffer:
                    self.errors.append("Discarded oversized unterminated TCP record")
                    self.buffer = b""
                    break
        except OSError as exc:
            self.errors.append(f"Sniffer TCP read failed: {exc}")
            self.close()

        records = []
        while b"\n" in self.buffer and len(records) < max(0, int(max_messages)):
            line, self.buffer = self.buffer.split(b"\n", 1)
            if not line.strip():
                continue
            try:
                raw = json.loads(line.decode("utf-8"))
                records.append(normalize_traffic_message(raw))
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, AttributeError) as exc:
                self.errors.append(f"Skipped malformed TCP record: {exc}")
        return records

    def close(self):
        if self.socket is not None:
            try:
                self.socket.close()
            except OSError:
                pass
            self.socket = None
