"""Cálculo de estatísticas gerais de tráfego a partir das entradas do log."""

from __future__ import annotations

from collections import Counter
from datetime import timedelta

import numpy as np

from logsentinel.models import LogEntry, TrafficSummary


def requests_per_minute(entries: list[LogEntry]) -> np.ndarray:
    """Conta requisições por minuto, incluindo minutos sem acesso (valor 0).

    Cada posição do array representa um minuto a partir do primeiro acesso.
    Considerar os minutos "vazios" é importante para que a média e o desvio
    padrão reflitam o tráfego real, e não só os momentos de atividade.
    """
    if not entries:
        return np.zeros(0, dtype=int)

    minutes = [e.timestamp.replace(second=0, microsecond=0) for e in entries]
    start = min(minutes)
    offsets = np.array(
        [int((m - start).total_seconds() // 60) for m in minutes]
    )
    # bincount conta quantas vezes cada índice aparece; índices ausentes = 0.
    return np.bincount(offsets)


def summarize(entries: list[LogEntry], top_n: int = 5) -> TrafficSummary:
    """Gera o resumo estatístico do tráfego."""
    if top_n < 1:
        raise ValueError("top_n deve ser maior ou igual a 1.")
    if not entries:
        return TrafficSummary()

    ip_counter = Counter(e.ip for e in entries)
    path_counter = Counter(e.path for e in entries)
    status_counter = Counter(e.status for e in entries)

    errors = sum(n for status, n in status_counter.items() if status >= 400)
    start = min(e.timestamp for e in entries)
    end = max(e.timestamp for e in entries)

    rpm = requests_per_minute(entries)
    peak_index = int(np.argmax(rpm))
    first_minute = start.replace(second=0, microsecond=0)

    return TrafficSummary(
        total_requests=len(entries),
        unique_ips=len(ip_counter),
        start=start,
        end=end,
        status_counts=dict(sorted(status_counter.items())),
        top_ips=ip_counter.most_common(top_n),
        top_paths=path_counter.most_common(top_n),
        error_rate=round(errors / len(entries) * 100, 2),
        total_bytes=sum(e.size for e in entries),
        rpm_mean=round(float(np.mean(rpm)), 2),
        rpm_std=round(float(np.std(rpm)), 2),
        rpm_p95=round(float(np.percentile(rpm, 95)), 2),
        peak_minute=first_minute + timedelta(minutes=peak_index),
        peak_requests=int(rpm[peak_index]),
    )
