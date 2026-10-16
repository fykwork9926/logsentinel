"""Regras de detecção de comportamento suspeito em logs de acesso.

Cada função `detect_*` recebe a lista de entradas e devolve uma lista de
alertas. Separar as regras assim facilita testá-las isoladamente e
adicionar novas detecções no futuro.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from urllib.parse import unquote

import numpy as np

from logsentinel.models import Alert, LogEntry, Severity

LOGIN_KEYWORDS = ("login", "signin", "auth", "wp-admin")

# Trechos que indicam tentativa de exploração (comparados em minúsculas,
# depois de decodificar a URL: "%27" vira "'", "%3C" vira "<" etc.).
EXPLOIT_PATTERNS: dict[str, tuple[str, ...]] = {
    "Arquivo sensível": (
        "/.env", "/.git", "/.htaccess", "/config.php", "/phpmyadmin",
        "/backup",
    ),
    "Path traversal": ("../", "/etc/passwd"),
    "SQL injection": ("' or", "union select", "sleep(", "' --"),
    "XSS": ("<script", "javascript:", "onerror="),
}

# Ferramentas de ataque/varredura que se identificam no User-Agent.
SUSPICIOUS_AGENTS = (
    "sqlmap", "nikto", "nmap", "masscan", "dirbuster",
    "gobuster", "wpscan", "hydra", "zgrab",
)


@dataclass(frozen=True)
class DetectionConfig:
    """Limites (thresholds) usados pelas regras de detecção."""

    brute_force_threshold: int = 10
    scan_threshold: int = 20
    flood_zscore: float = 3.0
    flood_min_requests: int = 100

    def __post_init__(self) -> None:
        # Validação simples para evitar configurações sem sentido.
        for name in ("brute_force_threshold", "scan_threshold",
                     "flood_min_requests"):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} deve ser maior que zero.")
        if self.flood_zscore <= 0:
            raise ValueError("flood_zscore deve ser maior que zero.")


def _is_login_path(path: str) -> bool:
    """Indica se a rota parece ser de autenticação."""
    lower = path.lower()
    return any(keyword in lower for keyword in LOGIN_KEYWORDS)


def detect_brute_force(
    entries: list[LogEntry], config: DetectionConfig
) -> list[Alert]:
    """Muitas falhas de login (401/403) vindas do mesmo IP."""
    failures: Counter[str] = Counter()
    successes: set[str] = set()

    for entry in entries:
        if entry.method != "POST" or not _is_login_path(entry.path):
            continue
        if entry.status in (401, 403):
            failures[entry.ip] += 1
        elif entry.status in (200, 302):
            successes.add(entry.ip)

    alerts = []
    for ip, count in failures.items():
        if count < config.brute_force_threshold:
            continue
        description = f"{count} falhas de autenticação em rotas de login"
        severity = Severity.MEDIUM
        # Login bem-sucedido depois de várias falhas = possível invasão.
        if ip in successes:
            description += ", seguidas de um login BEM-SUCEDIDO"
            severity = Severity.HIGH
        alerts.append(Alert(ip, "Força bruta", severity, description, count))
    return alerts


def detect_scanning(
    entries: list[LogEntry], config: DetectionConfig
) -> list[Alert]:
    """Muitos caminhos diferentes retornando 404 (varredura de diretórios)."""
    not_found: defaultdict[str, set[str]] = defaultdict(set)
    for entry in entries:
        if entry.status == 404:
            not_found[entry.ip].add(entry.path)

    return [
        Alert(
            ip,
            "Varredura de diretórios",
            Severity.MEDIUM,
            f"{len(paths)} caminhos diferentes retornaram 404",
            len(paths),
        )
        for ip, paths in not_found.items()
        if len(paths) >= config.scan_threshold
    ]


def detect_flood(
    entries: list[LogEntry], config: DetectionConfig
) -> list[Alert]:
    """IPs com volume de requisições muito acima da média (z-score)."""
    counts_by_ip = Counter(entry.ip for entry in entries)
    if len(counts_by_ip) < 3:
        return []  # poucos IPs: estatística não é confiável

    ips = list(counts_by_ip)
    counts = np.array([counts_by_ip[ip] for ip in ips], dtype=float)
    mean, std = counts.mean(), counts.std()
    if std == 0:
        return []  # todos os IPs com o mesmo volume

    # z-score: quantos desvios padrão cada IP está acima da média.
    z_scores = (counts - mean) / std

    alerts = []
    for ip, count, z in zip(ips, counts, z_scores):
        if z >= config.flood_zscore and count >= config.flood_min_requests:
            alerts.append(Alert(
                ip,
                "Excesso de requisições",
                Severity.HIGH,
                f"{int(count)} requisições ({z:.1f} desvios padrão acima "
                f"da média de {mean:.1f} por IP)",
                int(count),
            ))
    return alerts


def detect_exploit_attempts(entries: list[LogEntry]) -> list[Alert]:
    """URLs com padrões típicos de ataques (SQLi, XSS, arquivos sensíveis)."""
    hits: Counter[tuple[str, str]] = Counter()
    for entry in entries:
        decoded = unquote(entry.path).lower()
        for attack, patterns in EXPLOIT_PATTERNS.items():
            if any(pattern in decoded for pattern in patterns):
                hits[(entry.ip, attack)] += 1

    return [
        Alert(
            ip,
            f"Tentativa de exploração ({attack})",
            Severity.HIGH,
            f"{count} {'requisição' if count == 1 else 'requisições'} "
            f"com padrão de {attack}",
            count,
        )
        for (ip, attack), count in hits.items()
    ]


def detect_suspicious_agents(entries: list[LogEntry]) -> list[Alert]:
    """User-Agents de ferramentas conhecidas de ataque/varredura."""
    hits: Counter[str] = Counter()
    tool_by_ip: dict[str, str] = {}
    for entry in entries:
        agent = entry.user_agent.lower()
        for tool in SUSPICIOUS_AGENTS:
            if tool in agent:
                hits[entry.ip] += 1
                tool_by_ip[entry.ip] = tool
                break

    return [
        Alert(
            ip,
            "Ferramenta de ataque",
            Severity.MEDIUM,
            f"User-Agent identificado como '{tool_by_ip[ip]}'",
            count,
        )
        for ip, count in hits.items()
    ]


def run_all_detectors(
    entries: list[LogEntry], config: DetectionConfig | None = None
) -> list[Alert]:
    """Executa todas as regras e ordena os alertas por gravidade."""
    config = config or DetectionConfig()
    alerts = [
        *detect_brute_force(entries, config),
        *detect_scanning(entries, config),
        *detect_flood(entries, config),
        *detect_exploit_attempts(entries),
        *detect_suspicious_agents(entries),
    ]
    alerts.sort(key=lambda a: (-a.severity.rank, -a.occurrences, a.ip))
    return alerts
