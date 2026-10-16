"""Testes da leitura e interpretação das linhas de log."""

import tempfile
import unittest
from pathlib import Path

from logsentinel.parser import LogFileError, parse_file, parse_line

VALID_LINE = ('203.0.113.10 - - [15/Jan/2026:14:00:01 -0300] '
              '"GET /produtos HTTP/1.1" 200 5120 "-" "Mozilla/5.0"')


class TestParseLine(unittest.TestCase):
    def test_valid_combined_line(self) -> None:
        entry = parse_line(VALID_LINE)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.ip, "203.0.113.10")
        self.assertEqual(entry.method, "GET")
        self.assertEqual(entry.path, "/produtos")
        self.assertEqual(entry.status, 200)
        self.assertEqual(entry.size, 5120)
        self.assertEqual(entry.user_agent, "Mozilla/5.0")
        self.assertEqual(entry.timestamp.hour, 14)

    def test_common_log_format_without_user_agent(self) -> None:
        line = ('10.0.0.1 - - [15/Jan/2026:14:00:01 -0300] '
                '"GET / HTTP/1.1" 304 -')
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.size, 0)
        self.assertEqual(entry.user_agent, "-")

    def test_malformed_line_returns_none(self) -> None:
        self.assertIsNone(parse_line("isso não é um log"))

    def test_invalid_date_returns_none(self) -> None:
        line = VALID_LINE.replace("15/Jan/2026", "99/Xyz/2026")
        self.assertIsNone(parse_line(line))


class TestParseFile(unittest.TestCase):
    def test_counts_valid_and_invalid_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "access.log"
            path.write_text(f"{VALID_LINE}\nlixo\n\n{VALID_LINE}\n",
                            encoding="utf-8")
            result = parse_file(path)
        self.assertEqual(len(result.entries), 2)
        self.assertEqual(result.invalid_lines, 1)
        self.assertEqual(result.total_lines, 3)  # linha em branco ignorada

    def test_missing_file_raises_error(self) -> None:
        with self.assertRaises(LogFileError):
            parse_file("arquivo/que/nao/existe.log")


if __name__ == "__main__":
    unittest.main()
