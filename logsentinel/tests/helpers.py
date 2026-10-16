"""Funções auxiliares compartilhadas pelos testes."""

from datetime import datetime, timedelta, timezone

from logsentinel.models import LogEntry

BASE = datetime(2026, 1, 15, 14, 0, tzinfo=timezone(timedelta(hours=-3)))


def make_entry(ip: str = "203.0.113.10", path: str = "/",
               status: int = 200, method: str = "GET",
               agent: str = "Mozilla/5.0", minute: int = 0) -> LogEntry:
    """Cria uma LogEntry com valores padrão, alterando só o necessário."""
    return LogEntry(ip=ip, timestamp=BASE + timedelta(minutes=minute),
                    method=method, path=path, status=status, size=100,
                    user_agent=agent)
