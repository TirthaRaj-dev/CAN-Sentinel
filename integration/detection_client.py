"""Clients for consuming Member 3's intrusion detection results.

Supported transports: in-process queue, appended JSONL file, and TCP JSONL.
Malformed records are skipped and listed in ``errors`` so a bad detector event
cannot crash the dashboard. Confirm the real transport with Member 3.
"""
import json
import queue
import socket
from pathlib import Path

from integration.adapter import normalize_detection_result


class DetectionClientError(RuntimeError):
    """Raised for invalid configuration or connection failures."""


class QueueDetectionClient:
    """Consume raw detector dictionaries submitted to a Python queue."""
    def __init__(self, result_queue=None):
        self.result_queue = result_queue if result_queue is not None else queue.Queue()
        self.errors = []

    def submit(self, result):
        self.result_queue.put(result)

    def poll(self, max_messages=100):
        self.errors = []
        results = []
        for _ in range(max(0, int(max_messages))):
            try:
                raw = self.result_queue.get_nowait()
            except queue.Empty:
                break
            try:
                results.append(normalize_detection_result(raw))
            except (TypeError, ValueError, AttributeError) as exc:
                self.errors.append(f"Invalid queued detection result: {exc}")
        return results

    def close(self):
        pass


class JsonlFileDetectionClient:
    """Read newly appended newline-delimited JSON detector results."""
    def __init__(self, path, start_at_end=True):
        if not str(path).strip():
            raise ValueError("A detection JSONL file path is required")
        self.path = Path(path)
        self.offset = self.path.stat().st_size if start_at_end and self.path.exists() else 0
        self.errors = []
        self.pending_lines = []

    def poll(self, max_messages=100):
        self.errors = []
        if not self.path.exists():
            return []
        try:
            size = self.path.stat().st_size
            if size < self.offset:
                self.offset = 0
                self.pending_lines.clear()
            with self.path.open("rb") as stream:
                stream.seek(self.offset)
                chunk = stream.read()
                self.offset = stream.tell()
        except OSError as exc:
            self.errors.append(f"Could not read detection file: {exc}")
            return []
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
        results = []
        while self.pending_lines and len(results) < max(0, int(max_messages)):
            line = self.pending_lines.pop(0)
            if not line.strip():
                continue
            try:
                results.append(normalize_detection_result(json.loads(line)))
            except (json.JSONDecodeError, TypeError, ValueError, AttributeError) as exc:
                self.errors.append(f"Skipped malformed detection JSONL record: {exc}")
        return results

    def close(self):
        pass


class TcpJsonlDetectionClient:
    """Consume newline-delimited JSON detector results from a TCP server."""
    def __init__(self, host="127.0.0.1", port=8766, connect_timeout=0.5):
        self.host, self.port = str(host), int(port)
        self.socket = None
        self.buffer = b""
        self.errors = []
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(float(connect_timeout))
        try:
            sock.connect((self.host, self.port))
        except OSError as exc:
            sock.close()
            raise DetectionClientError(
                f"Could not connect to detector at {self.host}:{self.port}: {exc}"
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
                    self.errors.append("Detector TCP connection closed")
                    self.close()
                    break
                self.buffer += chunk
                if len(self.buffer) > 1_000_000 and b"\n" not in self.buffer:
                    self.errors.append("Discarded oversized unterminated detector record")
                    self.buffer = b""
                    break
        except OSError as exc:
            self.errors.append(f"Detector TCP read failed: {exc}")
            self.close()
        results = []
        while b"\n" in self.buffer and len(results) < max(0, int(max_messages)):
            line, self.buffer = self.buffer.split(b"\n", 1)
            if not line.strip():
                continue
            try:
                raw = json.loads(line.decode("utf-8"))
                results.append(normalize_detection_result(raw))
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, AttributeError) as exc:
                self.errors.append(f"Skipped malformed detector TCP record: {exc}")
        return results

    def close(self):
        if self.socket is not None:
            try:
                self.socket.close()
            except OSError:
                pass
            self.socket = None
