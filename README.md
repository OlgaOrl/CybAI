# CybAI

Cybersecurity AI tool for IT administrators. Scans infrastructure for vulnerabilities, analyzes risks using Claude AI, and sends alerts about critical security issues. All output in Estonian. Complies with KüTS, E-ITS, and OWASP standards.

**Tech stack:** Python 3.11+, Flask, Claude API, Bootstrap 5, pytest

## Quick Start

```bash
git clone https://github.com/OlgaOrl/CybAI.git
cd CybAI
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
cp .env.example .env      # fill in your keys
pre-commit install
```

### Run

```bash
flask run
# Open http://127.0.0.1:5000
```

### Test

```bash
pytest
```

## Documentation

| Document | Description |
|----------|-------------|
| [docs/GITHUB_WORKFLOW.md](docs/GITHUB_WORKFLOW.md) | Step-by-step guide: branches, commits, PRs, merge process |
| [CLAUDE.md](CLAUDE.md) | Engineering policy, TDD rules, code quality standards |
| [docs/CYBERSECURITY_STANDARDS.md](docs/CYBERSECURITY_STANDARDS.md) | Applicable laws and standards (KüTS, E-ITS, OWASP) |

## Start Here

1. Read [docs/GITHUB_WORKFLOW.md](docs/GITHUB_WORKFLOW.md) — how we work
2. Read [CLAUDE.md](CLAUDE.md) — project rules
3. Check the [Project Board](https://github.com/users/OlgaOrl/projects/6) — story order and status
4. Pick an issue from [GitHub Issues](https://github.com/OlgaOrl/CybAI/issues)
5. Follow the workflow: `issue → branch → tests → code → PR → squash merge`
