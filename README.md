# MCP-VulnLab

**Automated Static AST & Dynamic Sandbox Vulnerability Auditor for Open-Source MCP Servers & LLM Tool Frameworks.**

## Core Capabilities
1. **Static AST & Sink Auditor:** Scans Python & TypeScript MCP server codebases for unsanitized `subprocess`/`eval` command injection, SSRF in fetch/URL tools, path traversal in filesystem tools, SQL injection, and schema-poisoning vectors ("tool description shadowing").
2. **Dynamic Adversarial Tool Harness:** Boots target tool definitions against mutated adversarial JSON-RPC inputs & tracks side-effects without executing destructive host commands.
3. **Upstream-Ready `garak` Probe Module:** Drop-in custom probe classes for LLM tool-shadowing and indirect-injection exfiltration testing.

## Static source review

Install with `pip install -e '.[test]'`. Run `mcp-vulnlab . --format sarif`
for offline review of local MCP tool source files. Findings are review
candidates. Python tracking is intraprocedural and conservative. The JS/TS
pass matches source patterns in MCP modules without resolving data flow.
The source auditor does not import or execute modules under review.
