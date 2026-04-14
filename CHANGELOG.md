# Changelog

## [0.2.0] — 2026-04-14

### Added
- GitHub Action `trusthandoff/agentverif-action` — sign and verify agent ZIPs in CI
- HuggingFace Space — sign agents online without CLI
  https://huggingface.co/spaces/Agentverif/Agentverif
- LangChain integration — `verify_tool` and `sign_tool`
  `from agentverif_sign.langchain_tool import verify_tool`
- Claude MCP server — verify agents directly in Claude
  `https://mcp.agentverif.com`
- `sign.agentverif.com` — online signing redirect
- `agentverif.com/mcp` — dedicated MCP documentation page
- `agentverif.com/privacy` — privacy policy
- `agentverif.com/terms` — terms of service

### Fixed
- Scanner graceful degradation on HTTP errors
- CI permanent fix — only real test failures break build

## [0.1.2] — 2026-04-10
- Initial PyPI release
- Ed25519 signing support
- OWASP LLM Top 10 scanning
- verify.agentverif.com live
