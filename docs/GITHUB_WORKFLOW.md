# GitHub Workflow

## Setup

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

## Workflow

Every change follows this process:

### 1. Issue

Pick an existing issue or create a new one. No work without an issue.

### 2. Branch

Create a branch from `main`. Name includes issue number:

```bash
git checkout main
git pull origin main
git checkout -b <issue-number>-<short-description>
```

Examples:
```
1-project-setup
6-infrastructure-scanner
```

### 3. TDD — Write tests FIRST

Write failing tests based on acceptance criteria from the issue:

- **Unit tests** → `tests/unit/`
- **E2E tests** → `tests/e2e/`

```bash
pytest  # all tests must FAIL (RED)
```

### 4. Write code

Write minimum code to make all tests pass:

```bash
pytest  # all tests must PASS (GREEN)
```

### 5. Refactor

Clean up code while keeping tests green.

### 6. Commit

```bash
git add <files>
git commit -m "feat: short description (#issue-number)"
```

Pre-commit hooks will automatically run linting and formatting.

Commit message format (conventional commits):
- `feat:` — new feature
- `fix:` — bug fix
- `chore:` — setup, config, maintenance
- `docs:` — documentation
- `test:` — tests only
- `refactor:` — code refactoring

### 7. Push

```bash
git push -u origin <branch-name>
```

CI (GitHub Actions) will automatically run tests and linting.

### 8. Pull Request

Create a PR on GitHub:
- Title: short description
- Body: what was changed and why, link to issue (`Closes #issue-number`)
- PR must be small — one issue per PR, max ~400 lines

### 9. Review

PR is reviewed against:
- Acceptance criteria from the issue
- Compliance standards (OWASP, KüTS, E-ITS) referenced in the issue
- Code quality (SOLID, DRY, no magic numbers)
- Tests pass (unit + e2e)

### 10. Merge

PR is merged via **squash merge** into `main`.

```
issue → branch → tests (RED) → code (GREEN) → refactor → commit (hooks) → push (CI) → PR → review → squash merge
```

## Project Standards

All code must comply with:
- **KüTS** — Estonian Cybersecurity Act
- **E-ITS** — Estonian Information Security Standard
- **OWASP Top 10** — Web application security

Each story's acceptance criteria references specific standards. See `CYBER_STANDARDS.md` for details.

## Rules

- No direct commits to `main`
- No production code without a failing test
- Every story requires both unit and e2e tests
- Pre-commit hooks must not be skipped (`--no-verify` is prohibited)
- CI must be green before merge
