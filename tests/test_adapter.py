import unittest
from integration.adapter import (
    apply_detection_to_traffic,
    normalize_detection_result,
    normalize_traffic_message,
    sample_integration_input,
)


class TrafficAdapterTests(unittest.TestCase):
    def test_normalizes_common_traffic_schema(self):
        actual = normalize_traffic_message({
            "timestamp": "2026-10-27T17:30:00Z",
            "canId": "0x100", "data": "0a ff", "state": "normal"
        })
        self.assertEqual(actual, {
            "timestamp": "2026-10-27T17:30:00Z", "can_id": "0X100",
            "payload": "0A FF", "status": "NORMAL"
        })

    def test_defaults_missing_status_to_normal(self):
        actual = normalize_traffic_message({"id": "0x101", "payload": "01 02"})
        self.assertEqual(actual["status"], "NORMAL")
        self.assertTrue(actual["timestamp"])

    def test_rejects_non_dictionary_traffic(self):
        with self.assertRaises(TypeError):
            normalize_traffic_message("0x100,01 02")

    def test_rejects_missing_can_id(self):
        with self.assertRaisesRegex(ValueError, "can_id"):
            normalize_traffic_message({"payload": "01"})

    def test_rejects_invalid_status(self):
        with self.assertRaisesRegex(ValueError, "status"):
            normalize_traffic_message({"can_id": "0x100", "payload": "00", "status": "MAYBE"})


class DetectionAdapterTests(unittest.TestCase):
    def test_normalizes_detection_aliases_and_severity(self):
        actual = normalize_detection_result({
            "ts": "2026-10-27T17:30:00Z", "id": "0x666", "level": "critical",
            "description": "Rate anomaly", "data": "de ad"
        })
        self.assertEqual(actual, {
            "timestamp": "2026-10-27T17:30:00Z", "can_id": "0X666",
            "severity": "CRITICAL", "reason": "Rate anomaly", "payload": "DE AD"
        })

    def test_rejects_missing_reason(self):
        with self.assertRaisesRegex(ValueError, "reason"):
            normalize_detection_result({"can_id": "0x666", "severity": "HIGH"})

    def test_rejects_unknown_severity(self):
        with self.assertRaisesRegex(ValueError, "severity"):
            normalize_detection_result({"can_id": "0x666", "severity": "URGENT", "reason": "x"})

    def test_applies_detection_without_overwriting_traffic_timestamp(self):
        traffic, alert = apply_detection_to_traffic(
            {"timestamp": "traffic-time", "can_id": "0x666", "payload": "de ad"},
            {"timestamp": "alert-time", "can_id": "0x666", "severity": "HIGH", "reason": "rate"},
        )
        self.assertEqual(traffic["status"], "SUSPICIOUS")
        self.assertEqual(traffic["timestamp"], "traffic-time")
        self.assertEqual(alert["timestamp"], "alert-time")
        self.assertEqual(alert["payload"], "DE AD")

    def test_sample_input_can_be_adapted(self):
        sample = sample_integration_input()
        traffic = normalize_traffic_message(sample["traffic"])
        alert = normalize_detection_result(sample["detection"])
        self.assertEqual(traffic["can_id"], alert["can_id"])
        self.assertEqual(alert["severity"], "HIGH")


if __name__ == "__main__":
    unittest.main()
