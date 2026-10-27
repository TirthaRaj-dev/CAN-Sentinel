"""Normalize sniffer messages and detection results for the CAN-Sentinel UI.

This module intentionally has no PyQt dependency so it can be tested in isolation.
The input aliases are compatibility conveniences, not confirmation of Member 2/3
implementation details. Agree on the contract with both members before live wiring.
"""
from datetime import datetime, timezone

TRAFFIC_STATUSES = {"NORMAL", "SUSPICIOUS"}
SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def _required_text(data, keys, label):
    for key in keys:
        value = data.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    raise ValueError(f"Missing required field: {label}")


def _timestamp(data):
    value = data.get("timestamp", data.get("time", data.get("ts")))
    if value is None or not str(value).strip():
        # UTC ISO-8601 makes generated timestamps unambiguous across modules.
        return datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    return str(value).strip()


def normalize_traffic_message(message):
    """Return the shared traffic schema: timestamp, can_id, payload, status.

    Accepted aliases: can_id/canId/id; payload/data; status/state. If status is
    absent, NORMAL is used as a neutral default; detector output should be applied
    separately using normalize_detection_result().
    """
    if not isinstance(message, dict):
        raise TypeError("Traffic message must be a dictionary")
    can_id = _required_text(message, ("can_id", "canId", "id"), "can_id")
    payload = _required_text(message, ("payload", "data"), "payload")
    status = str(message.get("status", message.get("state", "NORMAL"))).strip().upper()
    if status not in TRAFFIC_STATUSES:
        raise ValueError(f"status must be one of {sorted(TRAFFIC_STATUSES)}")
    return {
        "timestamp": _timestamp(message),
        "can_id": can_id.upper(),
        "payload": payload.upper(),
        "status": status,
    }


def normalize_detection_result(result):
    """Return a normalized alert with timestamp, can_id, severity and reason.

    Optional payload is retained when supplied. Severity is required and must be
    LOW/MEDIUM/HIGH/CRITICAL; reason must be a non-empty explanation from detector.
    """
    if not isinstance(result, dict):
        raise TypeError("Detection result must be a dictionary")
    can_id = _required_text(result, ("can_id", "canId", "id"), "can_id")
    severity = _required_text(result, ("severity", "level"), "severity").upper()
    if severity not in SEVERITIES:
        raise ValueError(f"severity must be one of {sorted(SEVERITIES)}")
    reason = _required_text(result, ("reason", "message", "description"), "reason")
    normalized = {
        "timestamp": _timestamp(result),
        "can_id": can_id.upper(),
        "severity": severity,
        "reason": reason,
    }
    payload = result.get("payload", result.get("data"))
    if payload is not None:
        normalized["payload"] = str(payload).strip().upper()
    return normalized


def apply_detection_to_traffic(traffic_message, detection_result):
    """Return (normalized traffic, normalized alert) for a matching detection.

    The detector timestamp remains the alert timestamp; traffic timestamp remains
    the original frame timestamp. This avoids silently overwriting either event time.
    """
    traffic = normalize_traffic_message(traffic_message)
    alert = normalize_detection_result(detection_result)
    traffic["status"] = "SUSPICIOUS"
    if "payload" not in alert:
        alert["payload"] = traffic["payload"]
    return traffic, alert


def sample_integration_input():
    """Deterministic example data for testing without Members 2/3 running."""
    traffic = {
        "timestamp": "2026-10-27T17:30:00.000Z",
        "can_id": "0x666",
        "payload": "DE AD BE EF 00 11 22 33",
        "status": "NORMAL",
    }
    detection = {
        "timestamp": "2026-10-27T17:30:00.015Z",
        "can_id": "0x666",
        "severity": "HIGH",
        "reason": "Sample detector result: abnormal message frequency",
    }
    return {"traffic": traffic, "detection": detection}
