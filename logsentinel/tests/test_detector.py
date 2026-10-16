"""Testes das regras de detecção de ataques."""

import unittest

from logsentinel.detector import (
    DetectionConfig,
    detect_brute_force,
    detect_exploit_attempts,
    detect_flood,
    detect_scanning,
    detect_suspicious_agents,
    run_all_detectors,
)
from logsentinel.models import Severity
from tests.helpers import make_entry

CONFIG = DetectionConfig()


def login_failures(ip: str, count: int) -> list:
    return [make_entry(ip=ip, path="/login", method="POST", status=401)
            for _ in range(count)]


class TestBruteForce(unittest.TestCase):
    def test_detects_many_failures(self) -> None:
        alerts = detect_brute_force(login_failures("6.6.6.6", 12), CONFIG)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, Severity.MEDIUM)

    def test_ignores_few_failures(self) -> None:
        self.assertEqual(detect_brute_force(login_failures("1.1.1.1", 3),
                                            CONFIG), [])

    def test_success_after_failures_is_high(self) -> None:
        entries = login_failures("6.6.6.6", 12)
        entries.append(make_entry(ip="6.6.6.6", path="/login",
                                  method="POST", status=200))
        alerts = detect_brute_force(entries, CONFIG)
        self.assertEqual(alerts[0].severity, Severity.HIGH)


class TestOtherDetectors(unittest.TestCase):
    def test_scanning(self) -> None:
        entries = [make_entry(ip="7.7.7.7", path=f"/p{i}", status=404)
                   for i in range(25)]
        alerts = detect_scanning(entries, CONFIG)
        self.assertEqual(alerts[0].ip, "7.7.7.7")

    def test_flood_uses_zscore(self) -> None:
        entries = [make_entry(ip=f"10.0.0.{i}") for i in range(20)
                   for _ in range(10)]
        entries += [make_entry(ip="9.9.9.9") for _ in range(500)]
        alerts = detect_flood(entries, CONFIG)
        self.assertEqual([a.ip for a in alerts], ["9.9.9.9"])

    def test_flood_needs_enough_ips(self) -> None:
        entries = [make_entry(ip="9.9.9.9") for _ in range(500)]
        self.assertEqual(detect_flood(entries, CONFIG), [])

    def test_sql_injection_in_encoded_url(self) -> None:
        entry = make_entry(path="/produtos?id=1%27%20OR%201%3D1")
        alerts = detect_exploit_attempts([entry])
        self.assertIn("SQL injection", alerts[0].category)

    def test_suspicious_user_agent(self) -> None:
        entry = make_entry(agent="sqlmap/1.8")
        self.assertEqual(len(detect_suspicious_agents([entry])), 1)

    def test_normal_traffic_has_no_alerts(self) -> None:
        entries = [make_entry(ip=f"10.0.0.{i % 5}", path="/produtos")
                   for i in range(50)]
        self.assertEqual(run_all_detectors(entries), [])

    def test_invalid_config_raises(self) -> None:
        with self.assertRaises(ValueError):
            DetectionConfig(brute_force_threshold=0)


if __name__ == "__main__":
    unittest.main()
