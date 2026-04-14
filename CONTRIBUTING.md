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
pip install -r requirements-dev.txt
pytest tests/
```

## Guidelines
- Keep PRs focused — one feature per PR
- Add tests for new functionality
- Follow existing code style (ruff enforced)
- Open an issue before large changes

## Contact
hi@agentverif.com  
GitHub Issues: https://github.com/trusthandoff/agentverif/issues
