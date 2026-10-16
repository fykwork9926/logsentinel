"""Gerador de logs de exemplo para testar o LogSentinel sem um servidor real.

Os IPs usados pertencem a faixas reservadas para documentação (RFC 5737),
portanto não representam máquinas reais.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

TZ = timezone(timedelta(hours=-3))  # horário de Brasília
BASE_TIME = datetime(2026, 1, 15, 14, 0, 0, tzinfo=TZ)
WINDOW_MINUTES = 120

NORMAL_PATHS = [
    "/", "/produtos", "/produtos/42", "/produtos/7", "/carrinho",
    "/contato", "/sobre", "/blog", "/blog/python-para-iniciantes",
    "/static/css/style.css", "/static/js/app.js", "/favicon.ico", "/login",
]
BROWSER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) Mobile/15E148",
]
SCAN_PATHS = [
    "/.env", "/.git/config", "/.htaccess", "/config.php", "/phpmyadmin",
    "/backup.zip", "/backup.sql", "/wp-login.php", "/wp-admin", "/admin.php",
    "/administrator", "/server-status", "/old", "/test", "/dev", "/tmp",
    "/api/v1/users", "/api/debug", "/console", "/shell.php", "/cgi-bin/",
    "/db.sql", "/dump.sql", "/site.zip", "/www.zip", "/info.php",
    "/phpinfo.php", "/.DS_Store", "/actuator/env", "/vendor/",
]

Record = tuple[datetime, str]


def _line(ip: str, ts: datetime, method: str, path: str, status: int,
          size: int, agent: str) -> Record:
    """Monta uma linha no Combined Log Format."""
    text = (f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S %z")}] '
            f'"{method} {path} HTTP/1.1" {status} {size} "-" "{agent}"')
    return ts, text


def _normal_traffic(rng: random.Random, count: int) -> list[Record]:
    """Usuários comuns navegando pelo site."""
    ips = [f"203.0.113.{n}" for n in range(10, 50)]
    records = []
    for _ in range(count):
        ts = BASE_TIME + timedelta(seconds=rng.randint(0, WINDOW_MINUTES * 60))
        path = rng.choice(NORMAL_PATHS)
        status = rng.choices([200, 304, 404, 500], weights=[85, 10, 4, 1])[0]
        records.append(_line(rng.choice(ips), ts, "GET", path, status,
                             rng.randint(300, 9000),
                             rng.choice(BROWSER_AGENTS)))
    return records


def _attacks(rng: random.Random) -> list[Record]:
    """Cenários de ataque injetados no meio do tráfego normal."""
    records: list[Record] = []

    # 1) Força bruta no login, terminando com uma senha correta.
    start = BASE_TIME + timedelta(minutes=20)
    for i in range(45):
        status = 200 if i == 44 else 401
        records.append(_line("198.51.100.23", start + timedelta(seconds=i * 4),
                             "POST", "/login", status, 230,
                             "python-requests/2.31.0"))

    # 2) Varredura de diretórios com a ferramenta Nikto.
    start = BASE_TIME + timedelta(minutes=45)
    for i, path in enumerate(SCAN_PATHS):
        records.append(_line("198.51.100.77", start + timedelta(seconds=i * 2),
                             "GET", path, 404, 0, "Mozilla/5.0 (Nikto/2.5.0)"))

    # 3) Flood: centenas de requisições em poucos minutos.
    start = BASE_TIME + timedelta(minutes=70)
    for _ in range(400):
        ts = start + timedelta(seconds=rng.randint(0, 300))
        records.append(_line("192.0.2.150", ts, "GET", "/", 200, 512,
                             "Go-http-client/1.1"))

    # 4) SQL injection automatizado com sqlmap.
    start = BASE_TIME + timedelta(minutes=95)
    payloads = ["1%27%20OR%20%271%27%3D%271", "1%20UNION%20SELECT%20null--",
                "1%27%20AND%20SLEEP(5)--%20"]
    for i in range(12):
        path = f"/produtos?id={payloads[i % len(payloads)]}"
        records.append(_line("198.51.100.200", start + timedelta(seconds=i),
                             "GET", path, rng.choice([200, 500]), 1024,
                             "sqlmap/1.8#stable (https://sqlmap.org)"))

    # 5) Tentativa isolada de XSS na busca.
    records.append(_line("203.0.113.99", BASE_TIME + timedelta(minutes=101),
                         "GET", "/busca?q=%3Cscript%3Ealert(1)%3C/script%3E",
                         200, 2048, BROWSER_AGENTS[0]))
    return records


def generate_sample_log(output: str | Path, normal_lines: int = 1000,
                        seed: int = 42) -> Path:
    """Cria um arquivo de log realista com tráfego normal + ataques.

    O `seed` torna o resultado reproduzível: a mesma semente sempre
    gera o mesmo arquivo.
    """
    if normal_lines < 1:
        raise ValueError("normal_lines deve ser maior que zero.")

    rng = random.Random(seed)
    records = _normal_traffic(rng, normal_lines) + _attacks(rng)
    # Linhas corrompidas, para demonstrar o tratamento de entradas inválidas.
    records.append((BASE_TIME + timedelta(minutes=30), "linha corrompida ###"))
    records.append((BASE_TIME + timedelta(minutes=60),
                    '203.0.113.11 - - [data-invalida] "GET / HTTP/1.1" 200 1'))
    records.sort(key=lambda record: record[0])

    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(text for _, text in records) + "\n",
                    encoding="utf-8")
    return path
