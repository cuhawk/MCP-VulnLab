# MCP-VulnLab

MCP-VulnLab reviews local MCP tool source and metadata and validates in-memory tool mocks.
Install it with `pip install -e '.[test]'` on Python 3.12 or newer.

## Static source review

Run `mcp-vulnlab . --sarif` to emit SARIF 2.1.0 or omit the flag for JSON advisories.
The existing `--format sarif` option is also supported. Findings are review
candidates. Python tracks parameter flow through calls and returns of module-level
helpers in the same file. The analysis is conservative about branches and
reassignments. JavaScript and TypeScript use syntax-based checks for shell
commands, filesystem paths, HTTP destinations, formatted SQL, and hidden
Unicode controls in tool metadata. The source auditor reads source without
executing it. JSON and SARIF reports tag findings with applicable OWASP
Agentic Top 10 categories.

## Offline mock validation

Use `await run_mock(tool, arguments, schema, path_fields=("path",))` from
`mcp_vulnlab.schema_validator` with a trusted async mock that takes one
argument dictionary. It applies a compact UTF-8 JSON byte budget, validates
against JSON Schema Draft 2020-12, and normalizes selected top-level path
fields within a virtual POSIX root. The timeout covers the callable and
requires cooperative cancellation. Schema references resolve within the
document. Path normalization performs no filesystem access.

## Tool metadata review

Save a trusted SHA-256 snapshot and compare later tool metadata against it.

```sh
python -m mcp_vulnlab.garak_probes.mcp_tool_shadowing trusted.json --snapshot > baseline.json
python -m mcp_vulnlab.garak_probes.mcp_tool_shadowing tools.json --baseline baseline.json --format json
```

The scorer flags instruction overrides, duplicate normalized names, hidden
Unicode controls, and additions, removals, or changed records against the
snapshot. Hashes cover each complete record, including schemas and annotations,
with stable object key ordering. Name matching folds case, removes hidden
controls, and maps common Greek and Cyrillic lookalikes. Use `--format sarif`
for SARIF output. Omitting `--format` prints the original score array. A raw
trusted metadata array is also accepted for legacy description comparison.

To use the optional adapter with a garak installation that provides
`always.Passthru`, place `mcp_tool_shadowing.py` in that installation's
`garak/probes` directory and install MCP-VulnLab in the same Python
environment. Select `mcp_tool_shadowing.MCPToolShadowing` and configure
its `tools` list and optional `baseline` under
`plugins.probes.mcp_tool_shadowing.MCPToolShadowing`. The probe scores the
configured metadata and records the results without calling the generator.


## Benchmark and tests

Run `python benchmarks/run_bench.py` to reproduce the offline benchmark.
On the [74-fixture corpus](benchmarks/RESULTS.md), observed precision and
recall were both 100%, with 0 of 37 hardened fixtures flagged and a median
of 0.0799 ms per fixture. The pytest suite passed all 104 tests.
