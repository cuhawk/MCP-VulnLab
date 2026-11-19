# MCP-VulnLab

MCP-VulnLab reviews local MCP tool source and metadata and validates in-memory tool mocks.
Install it with `pip install -e '.[test]'` on Python 3.12 or newer.

## Static source review

Run `mcp-vulnlab . --sarif` to emit SARIF 2.1.0 or omit the flag for JSON advisories.
The existing `--format sarif` option is also supported. Findings are review
candidates. Python tracking is intraprocedural and conservative. The JS/TS
pass matches source patterns in MCP modules without resolving data flow.
The source auditor does not import or execute modules under review.

## Offline mock validation

Use `await run_mock(tool, arguments, schema, path_fields=("path",))` from
`mcp_vulnlab.schema_validator` with a trusted async mock that takes one
argument dictionary. It applies a compact UTF-8 JSON byte budget, validates
against JSON Schema Draft 2020-12, and normalizes selected top-level path
fields within a virtual POSIX root. The timeout covers the callable and
requires cooperative cancellation. Schema references resolve within the
document. Path normalization performs no filesystem access.

## Tool metadata review

Run `python -m mcp_vulnlab.garak_probes.mcp_tool_shadowing tools.json --baseline trusted.json`.
Each file contains a JSON array of tool records with a `name` and optional
`description`. The baseline is optional. The scorer flags instruction-override
patterns, duplicate normalized names, and descriptions that differ from the
trusted baseline. A score of 1 indicates a review candidate.

To use the optional adapter with a garak installation that provides
`always.Passthru`, place `mcp_tool_shadowing.py` in that installation's
`garak/probes` directory and install MCP-VulnLab in the same Python
environment. Select `mcp_tool_shadowing.MCPToolShadowing` and configure
its `tools` and optional `baseline` lists under
`plugins.probes.mcp_tool_shadowing.MCPToolShadowing`. The probe scores the
configured metadata and records the results without calling the generator.
