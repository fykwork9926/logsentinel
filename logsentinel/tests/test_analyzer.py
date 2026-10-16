"""Testes das estatísticas de tráfego."""

import unittest

from logsentinel.analyzer import requests_per_minute, summarize
from tests.helpers import make_entry


class TestAnalyzer(unittest.TestCase):
    def test_empty_entries_return_empty_summary(self) -> None:
        summary = summarize([])
        self.assertEqual(summary.total_requests, 0)
        self.assertIsNone(summary.start)

    def test_requests_per_minute_fills_gaps_with_zero(self) -> None:
        entries = [make_entry(minute=0), make_entry(minute=0),
                   make_entry(minute=3)]
        self.assertEqual(requests_per_minute(entries).tolist(), [2, 0, 0, 1])

    def test_summary_values(self) -> None:
        entries = [
            make_entry(ip="1.1.1.1", status=200),
            make_entry(ip="1.1.1.1", status=404, path="/x"),
            make_entry(ip="2.2.2.2", status=500, minute=1),
            make_entry(ip="3.3.3.3", status=200, minute=1),
        ]
        summary = summarize(entries, top_n=1)
        self.assertEqual(summary.total_requests, 4)
        self.assertEqual(summary.unique_ips, 3)
        self.assertEqual(summary.error_rate, 50.0)
        self.assertEqual(summary.top_ips, [("1.1.1.1", 2)])
        self.assertEqual(summary.status_counts, {200: 2, 404: 1, 500: 1})

    def test_invalid_top_n_raises(self) -> None:
        with self.assertRaises(ValueError):
            summarize([make_entry()], top_n=0)


if __name__ == "__main__":
    unittest.main()
