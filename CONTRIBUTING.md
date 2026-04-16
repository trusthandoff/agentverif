# Contributing to AgentVerif

AgentVerif is building the SSL/TLS standard for AI agents.
We welcome contributions from the community.

## Ways to contribute

### 1. Add framework integrations
We have LangChain. We need:
- **CrewAI** — `src/agentverif_sign/crewai_tool.py`
- **AutoGen** — `src/agentverif_sign/autogen_tool.py`
- **LlamaIndex** — `src/agentverif_sign/llamaindex_tool.py`
- **OpenAI Agents SDK** — `src/agentverif_sign/openai_tool.py`

Pattern to follow: `src/agentverif_sign/langchain_tool.py`

### 2. Improve the scanner
The OWASP LLM Top 10 scanner is in `src/agentverif_sign/scanner.py`.
Add new checks, improve scoring, add false positive detection.

### 3. Registry contributions
The registry API is in `api/server.py`.
Help build out the Pro tier features.

### 4. Documentation
- Framework-specific guides in `docs/`
- Translations (we have Chinese — need more)
- Tutorial videos

## Getting started

```bash
git clone https://github.com/trusthandoff/agentverif
cd agentverif
pip install -e ".[crypto]"
pip install -e ".[dev]"
.venv/bin/python -m pytest tests/ -v
```

> **Note:** always use the project virtualenv (`.venv/bin/python`), not system
> `python3`. Dependencies like `slowapi` are only installed in `.venv`.
> A `Makefile` shortcut is available: `make test`.

## Production service files

The live systemd service files at `/etc/systemd/system/` are NOT automatically
updated when `systemd/` files in this repo change. After editing
`systemd/agentverif-api.service` or `systemd/agentverif-mcp.service`, sync manually:

```bash
cp systemd/agentverif-api.service /etc/systemd/system/agentverif-api.service
systemctl daemon-reload && systemctl restart agentverif-api
```

## Guidelines
- Keep PRs focused — one feature per PR
- Add tests for new functionality
- Follow existing code style (ruff enforced)
- Open an issue before large changes

## Contact
hi@agentverif.com  
GitHub Issues: https://github.com/trusthandoff/agentverif/issues
