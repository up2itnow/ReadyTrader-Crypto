## Contributing

### Local setup
- Python 3.12+
- Install deps: `pip install -r requirements.txt`

### Checks
- Lint: `ruff check .`
- Tests: `pytest -q`
- Security: `bandit -q -r . -c bandit.yaml`
- Dependency audit: `pip-audit -r requirements.txt`

### Pull requests
- Keep changes focused and well-tested
- Update docs (`README.md`) for any new env vars or MCP tools

