# CybAI

## Project Overview

Cybersecurity AI tool for IT administrators. Scans infrastructure for vulnerabilities, analyzes risks using Claude AI, and sends alerts about critical security issues. All output in Estonian. Complies with KüTS, E-ITS, and OWASP standards.

## Tech Stack

* **Backend:** Python 3.11+, Flask
* **AI:** Anthropic Claude API
* **Frontend:** Jinja2 templates, Bootstrap 5 (CDN), custom CSS
* **Notifications:** smtplib (email), Twilio (SMS)
* **Testing:** pytest (unit + e2e)
* **Linting:** flake8, black
* **CI:** GitHub Actions

## Development

### Setup

```bash
git clone https://github.com/OlgaOrl/CybAI.git
cd CybAI
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env      # fill in your keys
pre-commit install
```

### Running

```bash
flask run
# Open http://127.0.0.1:5000
```

### Testing

```bash
pytest                    # all tests
pytest tests/unit/        # unit tests only
pytest tests/e2e/         # e2e tests only
pytest --cov=cybai        # with coverage report
```

### Linting

```bash
flake8 cybai/ tests/      # check style
black cybai/ tests/        # auto-format
pre-commit run --all-files # run all hooks
```

## AI Assistant Setup

### Claude Code

This file (`CLAUDE.md`) is automatically loaded by Claude Code. No extra setup needed. Claude Code will follow all rules below.

**Before starting work:**
1. Read the GitHub issue you are working on
2. Create a branch: `<issue-number>-<short-description>`
3. Follow TDD workflow (RED → GREEN → REFACTOR)
4. Run `pre-commit run --all-files` before committing
5. Run `pytest` — all tests must pass
6. Check DRY checklist before pushing

### Codex (OpenAI)

Create a file `AGENTS.md` in the project root with the same rules. Codex reads `AGENTS.md` automatically.

**Codex developers must also:**
1. Read this `CLAUDE.md` — it is the single source of truth for project rules
2. Copy the relevant sections into `AGENTS.md` or reference this file
3. Follow the same TDD workflow, branching, and PR rules
4. Run the same checks: `pytest`, `flake8`, `black`, `pre-commit`

### Developers without AI assistant

Follow the same workflow manually:
1. Pick an issue from [GitHub Issues](https://github.com/OlgaOrl/CybAI/issues)
2. Create a branch: `<issue-number>-<short-description>`
3. Write tests first (TDD), then code
4. Run `pytest` and `pre-commit run --all-files` before pushing
5. Create a PR, link to issue (`Closes #issue-number`)

## .gitignore (required)

The following must NEVER be committed:

```
venv/
__pycache__/
*.pyc
.env
logs.csv
.pytest_cache/
htmlcov/
*.egg-info/
dist/
build/
.coverage
```

## Pre-commit Hooks (required)

Pre-commit hooks run automatically on every `git commit`. They must check:

* **black** — code formatting
* **flake8** — code style and errors
* **trailing whitespace** — no trailing spaces
* **end-of-file-fixer** — files end with newline
* **check-added-large-files** — no large files committed
* **check-merge-conflict** — no unresolved merge markers

Skipping hooks (`--no-verify`) is **prohibited**.

## CI Checks (GitHub Actions)

Every push and PR triggers:

* **pytest** — all tests must pass
* **flake8** — no lint errors
* **black --check** — code is formatted
* **coverage** — business logic ≥ 80%

PR cannot be merged if any check fails.

## Conventions

- Use clear, descriptive variable and function names
- Write tests for new functionality
- Keep commits atomic and well-described
- Commit messages use conventional commits: `feat:`, `fix:`, `chore:`, `docs:`, `test:`, `refactor:`
- All user-facing text in Estonian
- All code, comments, and commit messages in English

### TDD Workflow (MANDATORY)

Every story/feature/bugfix MUST follow strict TDD (Test-Driven Development):

1. **RED** — Write tests FIRST based on acceptance criteria. All tests MUST FAIL.
2. **GREEN** — Write the minimum code to make all tests pass.
3. **REFACTOR** — Clean up code while keeping tests green.

**Every story requires BOTH:**
- **Unit tests** in `tests/unit/` — business logic, individual functions, modules, edge cases
- **E2E tests** in `tests/e2e/` — full user flows, API request→response cycles, integration between components

**Test naming:**
- Files: `test_<module>.py` (e.g. `test_dashboard.py`, `test_scanner.py`, `test_analyzer.py`)
- Functions: `test_<what_it_does>` (e.g. `test_dashboard_returns_200`, `test_scan_detects_open_ports`)
- Each file starts with a comment linking to the story: `# Story #<number>: <title>`

**Rules:**
- NO production code without a failing test first
- Tests are derived from acceptance criteria in the user story
- Tests validate **behavior**, not implementation details
- Bug fixes MUST include a regression test that fails before the fix
- Story is NOT done until both unit and e2e tests pass

### Pre-push DRY Checklist (MANDATORY)

Before pushing, verify there is no code duplication:

* No copy-pasted logic — extract shared code into functions/modules
* No repeated HTML blocks — use Jinja2 template inheritance and includes
* No duplicated CSS — reuse Bootstrap classes; custom styles only when Bootstrap doesn't cover it
* No repeated test setup — use `conftest.py` fixtures
* No hardcoded values repeated in multiple places — use constants or config

## Project Structure

```
CybAI/
├── cybai/                  # application code
│   ├── __init__.py         # Flask app factory
│   ├── scanner.py          # infrastructure scanner
│   ├── analyzer.py         # AI risk analysis (Claude API)
│   ├── notifier.py         # email/SMS notifications
│   ├── routes.py           # API endpoints
│   ├── templates/          # Jinja2 templates
│   │   ├── base.html       # base layout (Bootstrap 5)
│   │   └── dashboard.html  # main dashboard
│   └── static/
│       └── style.css       # custom styles
├── tests/
│   ├── conftest.py         # shared fixtures
│   ├── unit/               # unit tests
│   └── e2e/                # end-to-end tests
├── .env.example            # environment variables template
├── .gitignore
├── .pre-commit-config.yaml
├── .github/
│   └── workflows/
│       └── ci.yml          # GitHub Actions CI
├── requirements.txt
├── CLAUDE.md               # this file — project rules
└── README.md
```

---

## Engineering Policy

### 1. Version Control and Workflow

* Every change must be preceded by an issue.
* All in-progress changes are developed in `feature` or `bugfix` branches.
* All branch names include the issue number they are associated with. E.g.: `124-fix-header`
* Each branch is associated with only one issue.
* Direct commits to `main` that are incomplete and/or not associated with an issue are strictly prohibited.
* `main` branch must always be deployable and pass all tests.
* `main` branch commit messages use a consistent format (conventional commits, connextra, etc.).
* PRs are merged via **squash merge** into `main` — all branch commits are squashed into one clean commit.

---

#### 1.1 Issue Types and Format (**mandatory**)

##### Feature issue

**Title**

```
As a [role] I [can/want to] [action] so that [benefit]
```

**Body**

```
[1–3 sentences explaining in English why this functionality is needed and what problem it solves]

**Acceptance criteria**

* One sentence per line
* Starts with a capital letter
* Declarative and testable
* No numbering
* No implementation duplication
* May use Given–When–Then structure
```

Acceptance criteria form a **contract** and **testing basis** – code is complete only when all conditions are met.

---

##### Bug issue

**Title**

```
Bug: [short and specific description]
```

**Body**

```
1. Reproduction steps
[Clear and repeatable steps to reproduce the bug]

Expected:
[Description of expected behavior]

Actual:
[Description of actual behavior]
```

* Bug issue must be reproducible.
* Bug-fix PR must include a regression test that fails before the fix and passes after.

### 2. Code Quality and Style

- Project uses consistent code formatting and linting enforced in CI.
- Code follows **SOLID** principles and avoids duplication (**DRY**).
- No "magic numbers", commented-out code blocks, or hardcoded config values.
- Functions are short, readable, and fulfill a single responsibility.
- Code is not merged if lint, build, or tests fail. This must be enforced automatically (pre-commit hooks).

### 3. Testing and Quality Control

* Business logic test coverage is at least **80%**; critical service coverage is higher.
* All user flows (e.g. authentication, payments, profile management, etc.) are covered by **E2E** tests.
* Every bug fix must include a regression test.
* Tests run automatically on every PR and a broken test blocks merge.
* Test data (fixtures/mocks) is separated from code and reusable.
* **Tests must not be built on mocked business logic.** Only external dependencies may be mocked (e.g. third-party services, but not database queries).
* **Every test must turn red if the corresponding situation or logic in code changes.** Tests must not duplicate implementation; tests must validate behavior, not mocked inputs.

### 4. CI/CD and Deploy Policy

- Build, test, and deploy are fully automated (may use staging server for autodeploy instead of live).
- Deployment relies on immutable infrastructure (Docker/k8s); no manual changes to production environment.
- Dependency versions are fixed (lock files) to ensure environment consistency.

### 5. Architecture and Documentation

- All significant architectural decisions are documented as **ADR**s.
- API documentation (REST/GraphQL) is kept up-to-date and auto-generated.
- Each module must have a short `README` (installation, running, testing).
- Project folder structure must be consistent (e.g. `src/`, `tests/`, `docs/`, `config/`).
- API changes must be backward-compatible or use versioning.

### 6. Security

- No passwords, keys, or tokens are stored in the codebase (.env files are not in Git).
- All inputs are validated; SQL and API queries use parameterization.
- Dependencies undergo regular automatic security scanning (SCA).
- Sensitive information (PII) is not logged and logs are sent to a centralized logging system.
- HTTPS (TLS 1.2+) is mandatory in production.
- Authorization checks always happen server-side, not only in the UI.

### 7. Logging, Monitoring and Incident Management

- Application must have a health-check endpoint or native health indicator.
- Logs are structured (JSON) and contain `trace_id` for request tracing.
- Project uses error tracking (Sentry, Rollbar, etc.) with real-time notifications.
- Incident handling has a clear escalation process and SLAs.

### 8. Pull Request Requirements

- PR must be small and address a single specific change.
- PR must include an explanation: what was changed and why (with ticket reference if needed).
- PRs affecting architecture or data model require Tech Lead approval.
- PR must not exceed the agreed maximum size (e.g. 400 lines), except for exceptions.

### 9. Databases and Data Management

- Database schema changes are made only with versioned **migration scripts**.
- Destructive changes (e.g. column deletion) require a multi-step deploy process.
- Database queries are optimized (indexes, N+1 problem avoidance).
- Developers have no direct write access to production database.

### 10. Performance and Scalability

- Time-consuming operations (e.g. email sending, file processing) run asynchronously as background jobs.
- Repeated and expensive queries use a caching strategy.
- Static content is served optimally (CDN, compression/minification).

---

### Minimum Compliance

The project is considered compliant when:
* all items **1.1–1.5**, **2.1–2.6**, **3.1–3.4**, **6.1–6.6**, and **9.1** are fulfilled,
* remaining categories are at least **80%** implemented.
