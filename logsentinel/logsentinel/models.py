"""Estruturas de dados (dataclasses) compartilhadas por todo o projeto."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    """Nível de gravidade de um alerta de segurança."""

    HIGH = "ALTA"
    MEDIUM = "MÉDIA"
    LOW = "BAIXA"

    @property
    def rank(self) -> int:
        """Valor numérico usado para ordenar alertas (maior = mais grave)."""
        return {"ALTA": 3, "MÉDIA": 2, "BAIXA": 1}[self.value]


@dataclass(frozen=True)
class LogEntry:
    """Representa uma única linha (requisição) do log de acesso."""

    ip: str
    timestamp: datetime
    method: str
    path: str
    status: int
    size: int
    user_agent: str = "-"


@dataclass
class ParseResult:
    """Resultado da leitura de um arquivo de log."""

    entries: list[LogEntry] = field(default_factory=list)
    total_lines: int = 0
    invalid_lines: int = 0


@dataclass
class Alert:
    """Um comportamento suspeito encontrado por uma regra de detecção."""

    ip: str
    category: str
    severity: Severity
    description: str
    occurrences: int

    def to_dict(self) -> dict[str, str | int]:
        """Converte o alerta em dicionário (usado na exportação JSON/CSV)."""
        return {
            "severity": self.severity.value,
            "category": self.category,
            "ip": self.ip,
            "occurrences": self.occurrences,
            "description": self.description,
        }


@dataclass
class TrafficSummary:
    """Estatísticas gerais do tráfego registrado no log."""

    total_requests: int = 0
    unique_ips: int = 0
    start: datetime | None = None
    end: datetime | None = None
    status_counts: dict[int, int] = field(default_factory=dict)
    top_ips: list[tuple[str, int]] = field(default_factory=list)
    top_paths: list[tuple[str, int]] = field(default_factory=list)
    error_rate: float = 0.0
    total_bytes: int = 0
    rpm_mean: float = 0.0
    rpm_std: float = 0.0
    rpm_p95: float = 0.0
    peak_minute: datetime | None = None
    peak_requests: int = 0

    def to_dict(self) -> dict[str, object]:
        """Converte o resumo em tipos compatíveis com JSON."""

        def iso(value: datetime | None) -> str | None:
            return value.isoformat() if value else None

        return {
            "total_requests": self.total_requests,
            "unique_ips": self.unique_ips,
            "start": iso(self.start),
            "end": iso(self.end),
            "status_counts": {
                str(k): v for k, v in self.status_counts.items()
            },
            "top_ips": [{"ip": ip, "requests": n} for ip, n in self.top_ips],
            "top_paths": [
                {"path": p, "requests": n} for p, n in self.top_paths
            ],
            "error_rate_percent": self.error_rate,
            "total_bytes": self.total_bytes,
            "requests_per_minute": {
                "mean": self.rpm_mean,
                "std": self.rpm_std,
                "p95": self.rpm_p95,
                "peak_minute": iso(self.peak_minute),
                "peak_requests": self.peak_requests,
            },
        }
