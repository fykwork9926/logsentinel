"""Apresentação dos resultados: relatório no terminal e exportação JSON/CSV."""

from __future__ import annotations

import csv
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from logsentinel.models import Alert, ParseResult, Severity, TrafficSummary

WIDTH = 64
SEVERITY_COLORS = {
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}


class ReportError(Exception):
    """Erro levantado quando não é possível salvar um relatório."""


class Style:
    """Aplica cores ANSI ao texto apenas quando estão habilitadas."""

    CODES = {"bold": "1", "dim": "2", "red": "31", "green": "32",
             "yellow": "33", "cyan": "36"}

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, *styles: str) -> str:
        if not self.enabled or not styles:
            return text
        codes = ";".join(self.CODES[s] for s in styles)
        return f"\033[{codes}m{text}\033[0m"


def should_use_color(disabled_by_user: bool = False) -> bool:
    """Decide se o terminal deve exibir cores."""
    # Respeita a convenção NO_COLOR (https://no-color.org).
    if disabled_by_user or os.environ.get("NO_COLOR"):
        return False
    if os.name == "nt":
        os.system("")  # ativa cores ANSI no prompt de comando do Windows
    return sys.stdout.isatty()


def _format_datetime(value: datetime | None) -> str:
    return value.strftime("%d/%m/%Y %H:%M:%S") if value else "-"


def _format_bytes(size: int) -> str:
    """Converte bytes em uma unidade legível (KB, MB...)."""
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GB"


def _bar(value: int, maximum: int, width: int = 30) -> str:
    """Barra horizontal proporcional, usada como mini gráfico."""
    if maximum <= 0:
        return ""
    return "█" * max(1, round(value / maximum * width))


def print_report(
    source: str | Path,
    parse_result: ParseResult,
    summary: TrafficSummary,
    alerts: list[Alert],
    use_color: bool = True,
) -> None:
    """Imprime o relatório completo no terminal."""
    s = Style(use_color)

    def section(title: str) -> None:
        print()
        print(s(f"▶ {title}", "bold", "cyan"))

    def row(label: str, value: object) -> None:
        print(f"  {label:.<28} {value}")

    print(s("═" * WIDTH, "dim"))
    print(s("  LogSentinel — Relatório de Análise de Logs", "bold"))
    print(s("═" * WIDTH, "dim"))
    row("Arquivo ", source)
    row("Período ", f"{_format_datetime(summary.start)} → "
                    f"{_format_datetime(summary.end)}")
    row("Linhas lidas ", f"{parse_result.total_lines} "
                         f"({parse_result.invalid_lines} inválidas)")

    section("VISÃO GERAL")
    row("Requisições ", summary.total_requests)
    row("IPs únicos ", summary.unique_ips)
    row("Volume transferido ", _format_bytes(summary.total_bytes))
    row("Taxa de erro (4xx/5xx) ", f"{summary.error_rate}%")

    section("REQUISIÇÕES POR MINUTO")
    row("Média ", summary.rpm_mean)
    row("Desvio padrão ", summary.rpm_std)
    row("Percentil 95 ", summary.rpm_p95)
    peak_time = summary.peak_minute
    peak = peak_time.strftime("%H:%M") if peak_time else "-"
    row("Pico ", f"{summary.peak_requests} req às {peak}")

    section("CÓDIGOS DE STATUS HTTP")
    biggest = max(summary.status_counts.values(), default=0)
    for status, count in summary.status_counts.items():
        if status < 400:
            color = "green"
        elif status < 500:
            color = "yellow"
        else:
            color = "red"
        bar = _bar(count, biggest)
        print(f"  {s(str(status), color)}  {bar:<30} {count}")

    section(f"TOP {len(summary.top_ips)} IPs")
    for ip, count in summary.top_ips:
        print(f"  {ip:<18} {count:>6} req")

    section(f"TOP {len(summary.top_paths)} ROTAS")
    for path, count in summary.top_paths:
        shown = path if len(path) <= 40 else path[:37] + "..."
        print(f"  {shown:<42} {count:>6} req")

    section(f"ALERTAS DE SEGURANÇA ({len(alerts)})")
    if not alerts:
        print(s("  Nenhuma atividade suspeita encontrada.", "green"))
    for alert in alerts:
        tag = s(f"[{alert.severity.value:^5}]", "bold",
                SEVERITY_COLORS[alert.severity])
        print(f"  {tag} {alert.ip:<16} {alert.category}")
        print(s(f"          └─ {alert.description}", "dim"))

    print()
    print(s("═" * WIDTH, "dim"))


def export_json(
    path: Path,
    source: str | Path,
    parse_result: ParseResult,
    summary: TrafficSummary,
    alerts: list[Alert],
) -> None:
    """Salva o relatório completo em JSON (fácil de integrar com outras
    ferramentas, como dashboards ou SIEMs)."""
    data = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "source": str(source),
        "lines": {
            "total": parse_result.total_lines,
            "invalid": parse_result.invalid_lines,
        },
        "summary": summary.to_dict(),
        "alerts": [alert.to_dict() for alert in alerts],
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as file:
            json.dump(data, file, ensure_ascii=False, indent=2)
    except OSError as exc:
        raise ReportError(f"não foi possível salvar {path}: {exc}") from exc


def export_csv(path: Path, alerts: list[Alert]) -> None:
    """Salva os alertas em CSV (abre direto no Excel/Google Sheets)."""
    fields = ["severity", "category", "ip", "occurrences", "description"]
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # utf-8-sig faz o Excel reconhecer os acentos corretamente.
        with path.open("w", encoding="utf-8-sig", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=fields)
            writer.writeheader()
            writer.writerows(alert.to_dict() for alert in alerts)
    except OSError as exc:
        raise ReportError(f"não foi possível salvar {path}: {exc}") from exc
