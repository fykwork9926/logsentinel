"""Interface de linha de comando (CLI) do LogSentinel."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from logsentinel import __version__
from logsentinel.analyzer import summarize
from logsentinel.detector import DetectionConfig, run_all_detectors
from logsentinel.models import Severity
from logsentinel.parser import LogFileError, parse_file
from logsentinel.reporter import (
    ReportError,
    export_csv,
    export_json,
    print_report,
    should_use_color,
)
from logsentinel.sample import generate_sample_log

# Códigos de saída: permitem usar a ferramenta em scripts e pipelines de CI.
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_HIGH_ALERT = 2


def _positive_int(value: str) -> int:
    """Validador do argparse que aceita apenas inteiros positivos."""
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"'{value}' não é um número inteiro."
        ) from exc
    if number < 1:
        raise argparse.ArgumentTypeError("o valor deve ser maior que zero.")
    return number


def _error(message: str) -> None:
    """Exibe mensagens de erro no stderr, separado da saída normal."""
    print(f"Erro: {message}", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    """Define os comandos e opções aceitos pela CLI."""
    parser = argparse.ArgumentParser(
        prog="logsentinel",
        description="Analisa logs de acesso de servidores web "
                    "e detecta atividades suspeitas.",
    )
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- comando: analyze -------------------------------------------------
    analyze = subparsers.add_parser(
        "analyze", help="analisa um arquivo de log de acesso"
    )
    analyze.add_argument("logfile", type=Path,
                         help="caminho do arquivo de log (Apache/Nginx)")
    analyze.add_argument("--top", type=_positive_int, default=5,
                         help="quantidade de itens nos rankings (padrão: 5)")
    analyze.add_argument("--json", type=Path, metavar="ARQUIVO",
                         help="exporta o relatório completo em JSON")
    analyze.add_argument("--csv", type=Path, metavar="ARQUIVO",
                         help="exporta os alertas em CSV")
    analyze.add_argument("--brute-force-threshold", type=_positive_int,
                         default=10, metavar="N",
                         help="falhas de login para alertar (padrão: 10)")
    analyze.add_argument("--scan-threshold", type=_positive_int,
                         default=20, metavar="N",
                         help="caminhos 404 distintos para alertar "
                              "(padrão: 20)")
    analyze.add_argument("--no-color", action="store_true",
                         help="desativa as cores no terminal")
    analyze.add_argument("--fail-on-high", action="store_true",
                         help="retorna código 2 se houver alerta ALTA")
    analyze.set_defaults(func=cmd_analyze)

    # --- comando: sample --------------------------------------------------
    sample = subparsers.add_parser(
        "sample", help="gera um log de exemplo com tráfego e ataques simulados"
    )
    sample.add_argument("-o", "--output", type=Path,
                        default=Path("data/sample_access.log"),
                        help="arquivo de saída "
                             "(padrão: data/sample_access.log)")
    sample.add_argument("-n", "--lines", type=_positive_int, default=1000,
                        help="requisições normais a gerar (padrão: 1000)")
    sample.add_argument("--seed", type=int, default=42,
                        help="semente aleatória para resultados reproduzíveis")
    sample.set_defaults(func=cmd_sample)

    return parser


def cmd_analyze(args: argparse.Namespace) -> int:
    """Executa o fluxo completo: ler → resumir → detectar → reportar."""
    try:
        result = parse_file(args.logfile)
    except LogFileError as exc:
        _error(str(exc))
        return EXIT_ERROR

    if not result.entries:
        _error("nenhuma linha válida encontrada. Confira se o arquivo "
               "está no formato Combined Log (Apache/Nginx).")
        return EXIT_ERROR

    config = DetectionConfig(
        brute_force_threshold=args.brute_force_threshold,
        scan_threshold=args.scan_threshold,
    )
    summary = summarize(result.entries, top_n=args.top)
    alerts = run_all_detectors(result.entries, config)

    print_report(args.logfile, result, summary, alerts,
                 use_color=should_use_color(args.no_color))

    try:
        if args.json:
            export_json(args.json, args.logfile, result, summary, alerts)
            print(f"Relatório JSON salvo em: {args.json}")
        if args.csv:
            export_csv(args.csv, alerts)
            print(f"Alertas CSV salvos em:   {args.csv}")
    except ReportError as exc:
        _error(str(exc))
        return EXIT_ERROR

    has_high = any(alert.severity is Severity.HIGH for alert in alerts)
    if args.fail_on_high and has_high:
        return EXIT_HIGH_ALERT
    return EXIT_OK


def cmd_sample(args: argparse.Namespace) -> int:
    """Gera o arquivo de log de exemplo."""
    try:
        path = generate_sample_log(args.output, args.lines, args.seed)
    except (OSError, ValueError) as exc:
        _error(f"não foi possível gerar o log: {exc}")
        return EXIT_ERROR

    print(f"Log de exemplo gerado em: {path}")
    print(f"Para analisar, rode: python -m logsentinel analyze {path}")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    """Ponto de entrada da aplicação. Retorna o código de saída."""
    # Evita erro de encoding ao imprimir símbolos (█, ▶) em terminais antigos.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nOperação cancelada pelo usuário.", file=sys.stderr)
        return 130
