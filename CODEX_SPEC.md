# Codex Cloud Implementation Specification: MCP-VulnLab
Build a complete Python 3.12+ AI/MCP vulnerability research toolkit (`src/mcp_vulnlab/`):
- `src/mcp_vulnlab/static_audit.py`: Python `ast` + TS/JS pattern taint auditor detecting vulnerable MCP `@mcp.tool()` / FastMCP / JSON-schema handlers (`subprocess(shell=True)`, `os.system`, unvalidated file `open()`/`Path` joins, unvalidated HTTP `requests`/`httpx` SSRF, unsafe `yaml.load`/`pickle`, hidden `<IMPORTANT>` prompt-injection instructions inside tool docstrings).
- `src/mcp_vulnlab/dynamic_fuzzer.py`: Mutational JSON-RPC payload generator testing path traversal (`../../`), command metacharacters, SSRF metadata URLs (`169.254.169.254`), and oversized schema DOS against mock/sandboxed tool handlers.
- `src/mcp_vulnlab/garak_probes/mcp_tool_shadowing.py`: Clean, well-documented NVIDIA `garak`-compatible probe module + standalone test runner.
- `examples/vulnerable_mcp_server.py`: Intentionally vulnerable educational MCP server fixture with documented advisories.
- `tests/`: 20+ `pytest` tests verifying static detection, dynamic fuzzing findings, SARIF/JSON advisory export, and zero false positives on patched handlers.
- `.github/workflows/ci.yml`: Automated pytest CI workflow.
