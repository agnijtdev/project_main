# DevSecOps Multi-Agent Framework

A Python-based DevSecOps workflow for analyzing code changes, validating suspected vulnerabilities in a sandboxed environment, proposing remediations, and checking that the fix does not regress existing behavior.

This project is organized as a reusable Python package named `devsecops_agent` and exposes a CLI for running scans against a local repository or a remote Git URL.

## What it does

The framework follows a closed-loop remediation flow:

1. Extracts a Git diff or PR context from a repository.
2. Identifies Python code candidates that may contain security issues.
3. Runs exploit or verification logic in an isolated sandbox.
4. Uses a multi-agent workflow (`attacker`, `patcher`, `critic`) to reason about the issue.
5. Applies and verifies a remediation patch.
6. Writes a markdown report and, optionally, creates a remediation branch with the final verified fix.

## Key features

- Diff-driven security analysis
- Multi-agent orchestration for exploit validation and remediation
- Sandbox execution via Docker or local execution
- LLM provider abstraction (`mock`, `ollama`, `openai`, `gemini`)
- CLI-based workflow for repository scanning and reporting
- Regression-focused patch verification
- Markdown reporting for candidate analysis and remediation results

## Repository layout

- `src/devsecops_agent/` — main Python package
  - `agents/` — attacker, patcher, critic, and shared agent logic
  - `context/` — diff and code-context extraction
  - `orchestrator/` — orchestration pipeline and workflow coordination
  - `sandbox/` — execution environment for exploit and regression checks
  - `schemas/` — structured request/response models
  - `llm/` — LLM integration points
  - `cli.py` — command-line entrypoint
  - `config.py` — environment-driven settings
- `tests/` — pytest suite for orchestrator, schema, critic, sandbox, and CLI behavior
- `benchmarks/` — benchmark applications used for validation scenarios
- `demo_app.py` — small Flask demo app used for example workflows
- `report.md`, `report_cmdi.md` — example output reports
- `.env.example` — environment template
- `Dockerfile.sandbox` — sandbox image definition

## Installation

```bash
git clone https://github.com/agnijtdev/project_main.git
cd project_main
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
cp .env.example .env
```

## Configuration

The project reads settings from a local `.env` file. A template is provided in `.env.example`.

Example configuration:

```env
LLM_PROVIDER=mock
SANDBOX_DRIVER=docker
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_DEFAULT_MODEL=qwen2.5-coder:7b
GEMINI_API_KEY=
OPENAI_API_KEY=
```

Supported values include:

- `LLM_PROVIDER`: `mock`, `ollama`, `openai`, `gemini`
- `SANDBOX_DRIVER`: `auto`, `docker`, `local`

## CLI usage

### Scan a local repository

```bash
devsecops-agent scan \
  --repo . \
  --base-branch main \
  --head-branch feature/my-change \
  --test-cmd "pytest -q" \
  --driver docker \
  --provider mock \
  --output-report reports/remediation_report.md
```

### Scan a remote Git repository

```bash
devsecops-agent scan \
  --repo https://github.com/example/project.git \
  --base-branch main \
  --head-branch feature/update \
  --driver docker
```

### Show the current version

```bash
devsecops-agent version
```

## Running tests

```bash
pytest -q
```

The suite covers:

- CLI remediation flow
- context extraction logic
- AST-based critic checks
- sandbox execution behavior
- orchestrator pipeline behavior
- schema validation

## Example app

`demo_app.py` is a minimal Flask application used to demonstrate scanning and validation behavior. It is not the main product itself; it is a lightweight example used in testing and demonstration flows.

## Notes

- The project is designed for Python 3.10+
- Containerized or local sandbox execution is supported depending on the selected driver
- Reporting is generated as markdown, which can be reviewed after each scan run

## License

This project is intended for research, experimentation, and security-focused automation workflows.
