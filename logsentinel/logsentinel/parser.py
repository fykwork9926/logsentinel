"""Leitura de arquivos de log no formato Apache/Nginx (Combined Log Format).

Exemplo de linha suportada:
    203.0.113.10 - - [15/Jan/2026:14:00:01 -0300] "GET / HTTP/1.1"
    200 512 "-" "Mozilla/5.0"
(no arquivo real, tudo fica em uma única linha)
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from logsentinel.models import LogEntry, ParseResult

# Expressão regular com grupos nomeados para cada campo da linha.
# A parte final (referer + user-agent) é opcional, então o formato
# "Common Log Format" (mais simples) também é aceito.
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?: "[^"]*" "(?P<user_agent>[^"]*)")?'
)
TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


class LogFileError(Exception):
    """Erro levantado quando o arquivo de log não pode ser lido."""


def parse_line(line: str) -> LogEntry | None:
    """Converte uma linha de texto em LogEntry.

    Retorna None quando a linha não segue o formato esperado, em vez de
    interromper o programa: logs reais frequentemente têm linhas corrompidas.
    """
    match = LOG_PATTERN.match(line.strip())
    if match is None:
        return None

    try:
        timestamp = datetime.strptime(match["timestamp"], TIMESTAMP_FORMAT)
        status = int(match["status"])
        size = 0 if match["size"] == "-" else int(match["size"])
    except ValueError:
        # Data inválida ou número malformado: tratamos como linha inválida.
        return None

    return LogEntry(
        ip=match["ip"],
        timestamp=timestamp,
        method=match["method"],
        path=match["path"],
        status=status,
        size=size,
        user_agent=match["user_agent"] or "-",
    )


def parse_file(path: str | Path) -> ParseResult:
    """Lê o arquivo linha a linha e devolve as entradas válidas.

    A leitura é feita em streaming (uma linha por vez), então o arquivo
    não precisa ser carregado inteiro na memória antes de ser processado.
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise LogFileError(f"arquivo não encontrado: {file_path}")

    result = ParseResult()
    try:
        # errors="replace" evita que um byte inválido derrube a leitura.
        with file_path.open(encoding="utf-8", errors="replace") as file:
            for line in file:
                if not line.strip():
                    continue  # ignora linhas em branco
                result.total_lines += 1
                entry = parse_line(line)
                if entry is None:
                    result.invalid_lines += 1
                else:
                    result.entries.append(entry)
    except PermissionError as exc:
        raise LogFileError(f"sem permissão para ler: {file_path}") from exc
    except OSError as exc:
        raise LogFileError(f"falha ao ler {file_path}: {exc}") from exc

    return result
