# 🛡️ LogSentinel

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![NumPy](https://img.shields.io/badge/NumPy-estatística-013243?logo=numpy)
![License](https://img.shields.io/badge/licença-MIT-green)
![Tests](https://github.com/fykwork9926/logsentinel/actions/workflows/tests.yml/badge.svg)

**LogSentinel** é uma ferramenta de linha de comando (CLI) que analisa logs de acesso de servidores web (**Apache/Nginx**), gera estatísticas de tráfego e **detecta automaticamente atividades suspeitas**, como força bruta, varredura de diretórios, flood de requisições e tentativas de SQL injection/XSS.

> 💡 **Problema real:** todo servidor web gera milhares de linhas de log por dia. Ler isso manualmente é inviável — o LogSentinel resume o tráfego e destaca em segundos o que merece atenção.

---

## ✨ Funcionalidades

- 📄 **Leitura de logs** no formato *Combined/Common Log Format* (padrão do Apache e Nginx), tolerante a linhas corrompidas.
- 📊 **Estatísticas de tráfego**: total de requisições, IPs únicos, volume transferido, taxa de erro, códigos HTTP e rankings de IPs e rotas.
- 📈 **Análise com NumPy**: média, desvio padrão, percentil 95 e pico de requisições por minuto.
- 🚨 **Detecção de ameaças**:
  | Regra | O que identifica | Severidade |
  |---|---|---|
  | Força bruta | Muitas falhas de login (401/403) do mesmo IP | MÉDIA / **ALTA** se houver login bem-sucedido depois |
  | Varredura de diretórios | Muitos caminhos diferentes retornando 404 | MÉDIA |
  | Excesso de requisições | IPs com volume anômalo (z-score) | ALTA |
  | Tentativa de exploração | SQL injection, XSS, path traversal, arquivos sensíveis (`.env`, `.git`) | ALTA |
  | Ferramenta de ataque | User-Agents como `sqlmap`, `nikto`, `nmap` | MÉDIA |
- 💾 **Exportação** em **JSON** (relatório completo) e **CSV** (alertas, abre direto no Excel).
- 🧪 **Gerador de logs de exemplo** com ataques simulados, para testar sem precisar de um servidor.
- ⚙️ **Pronto para automação**: códigos de saída padronizados e opção `--fail-on-high` para uso em scripts e pipelines de CI.

## 🛠️ Tecnologias utilizadas

- **Python 3.10+** — type hints, `dataclasses`, `enum`, `pathlib`
- **NumPy** — cálculos estatísticos e detecção de anomalias (z-score)
- **Biblioteca padrão**: `argparse` (CLI), `re` (regex), `collections`, `csv`, `json`, `unittest`
- **GitHub Actions** — testes automatizados em Python 3.10, 3.11 e 3.12

## 🚀 Instalação e execução

### 1. Clone o repositório
```bash
git clone https://github.com/SEU-USUARIO/logsentinel.git
cd logsentinel
```

### 2. Crie e ative um ambiente virtual
```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate
```

### 3. Instale as dependências
```bash
pip install -r requirements.txt
```

### 4. Gere um log de exemplo (opcional)
```bash
python -m logsentinel sample
```

### 5. Analise o log
```bash
python -m logsentinel analyze data/sample_access.log
```

## 💻 Exemplos de uso

```bash
# Análise básica
python -m logsentinel analyze /var/log/nginx/access.log

# Top 10 e exportação dos resultados
python -m logsentinel analyze data/sample_access.log --top 10 \
    --json reports/relatorio.json --csv reports/alertas.csv

# Limites de detecção personalizados
python -m logsentinel analyze access.log --brute-force-threshold 5 --scan-threshold 10

# Em automações: retorna código 2 se houver alerta de severidade ALTA
python -m logsentinel analyze access.log --fail-on-high --no-color

# Ajuda completa
python -m logsentinel analyze --help
```

### Exemplo de saída no terminal

```text
$ python -m logsentinel analyze data/sample_access.log
════════════════════════════════════════════════════════════════
  LogSentinel — Relatório de Análise de Logs
════════════════════════════════════════════════════════════════
  Arquivo .................... data/sample_access.log
  Período .................... 15/01/2026 14:00:05 → 15/01/2026 15:59:50
  Linhas lidas ............... 1490 (2 inválidas)

▶ VISÃO GERAL
  Requisições ................ 1488
  IPs únicos ................. 45
  Volume transferido ......... 4.8 MB
  Taxa de erro (4xx/5xx) ..... 9.01%

▶ REQUISIÇÕES POR MINUTO
  Média ...................... 12.4
  Desvio padrão .............. 16.62
  Percentil 95 ............... 26.5
  Pico ....................... 98 req às 15:12

▶ CÓDIGOS DE STATUS HTTP
  200  ██████████████████████████████ 1259
  304  ██                             95
  401  █                              44
  404  ██                             73
  500  █                              17

▶ TOP 5 IPs
  192.0.2.150           400 req
  198.51.100.23          45 req
  203.0.113.44           34 req
  203.0.113.30           34 req
  203.0.113.18           33 req

▶ TOP 5 ROTAS
  /                                             458 req
  /login                                        123 req
  /static/js/app.js                              91 req
  /blog/python-para-iniciantes                   83 req
  /produtos/42                                   83 req

▶ ALERTAS DE SEGURANÇA (8)
  [ALTA ] 192.0.2.150      Excesso de requisições
          └─ 400 requisições (6.6 desvios padrão acima da média de 33.1 por IP)
  [ALTA ] 198.51.100.23    Força bruta
          └─ 44 falhas de autenticação em rotas de login, seguidas de um login BEM-SUCEDIDO
  [ALTA ] 198.51.100.200   Tentativa de exploração (SQL injection)
          └─ 12 requisições com padrão de SQL injection
  [ALTA ] 198.51.100.77    Tentativa de exploração (Arquivo sensível)
          └─ 7 requisições com padrão de Arquivo sensível
  [ALTA ] 203.0.113.99     Tentativa de exploração (XSS)
          └─ 1 requisição com padrão de XSS
  [MÉDIA] 198.51.100.77    Varredura de diretórios
          └─ 30 caminhos diferentes retornaram 404
  [MÉDIA] 198.51.100.77    Ferramenta de ataque
          └─ User-Agent identificado como 'nikto'
  [MÉDIA] 198.51.100.200   Ferramenta de ataque
          └─ User-Agent identificado como 'sqlmap'

════════════════════════════════════════════════════════════════
```

### Códigos de saída

| Código | Significado |
|---|---|
| `0` | Análise concluída com sucesso |
| `1` | Erro (arquivo inexistente, sem permissão, formato inválido...) |
| `2` | Alertas de severidade ALTA encontrados (apenas com `--fail-on-high`) |

## 🧪 Testes

```bash
python -m unittest discover -v
```

## 📁 Estrutura de arquivos

```text
logsentinel/
├── .github/workflows/
│   └── tests.yml          # CI: roda os testes a cada push
├── data/
│   └── sample_access.log  # log de exemplo com ataques simulados
├── logsentinel/           # código-fonte do pacote
│   ├── __init__.py        # versão do projeto
│   ├── __main__.py        # permite rodar com "python -m logsentinel"
│   ├── cli.py             # comandos e argumentos da linha de comando
│   ├── models.py          # dataclasses (LogEntry, Alert, TrafficSummary...)
│   ├── parser.py          # leitura e interpretação das linhas de log
│   ├── analyzer.py        # estatísticas de tráfego (NumPy)
│   ├── detector.py        # regras de detecção de ameaças
│   ├── reporter.py        # relatório no terminal + exportação JSON/CSV
│   └── sample.py          # gerador de logs de exemplo
├── reports/               # relatórios exportados (ignorados pelo Git)
├── tests/                 # testes unitários (unittest)
├── .gitignore
├── LICENSE
├── README.md
└── requirements.txt
```

## 🗺️ Próximos passos

- [ ] Suporte a outros formatos de log (ex.: logs de autenticação SSH)
- [ ] Arquivo de configuração (`.toml`) para as regras de detecção
- [ ] Consulta de reputação de IPs em API pública (ex.: AbuseIPDB)
- [ ] Gráficos de tráfego com Matplotlib

## ⚠️ Aviso

Os IPs do log de exemplo pertencem a faixas reservadas para documentação (RFC 5737) e não representam máquinas reais. As regras de detecção são heurísticas de caráter educacional e não substituem um SIEM/IDS profissional.

## 📝 Licença

Distribuído sob a licença MIT. Veja [`LICENSE`](LICENSE) para mais detalhes.

---

Desenvolvido por **Fernando** · [LinkedIn](https://www.linkedin.com/in/SEU-PERFIL) · [GitHub](https://github.com/SEU-USUARIO)
