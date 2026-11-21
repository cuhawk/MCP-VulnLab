"""OWASP Top 10 for Agentic Applications (2026) report taxonomy."""

CATEGORIES = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse and Exploitation",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution (RCE)",
    "ASI06": "Memory and Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}
RULE_CATEGORIES = {
    "schema-shadowing": ("ASI01",),
    "instruction-override": ("ASI01",),
    "duplicate-tool-name": ("ASI02", "ASI04"),
    "hidden-unicode": ("ASI01", "ASI04"),
    "description-changed": ("ASI04",),
    "metadata-drift": ("ASI04",),
    "metadata-added": ("ASI04",),
    "metadata-removed": ("ASI04",),
    "command": ("ASI02", "ASI05"),
    "deserialization": ("ASI02", "ASI05"),
    "network": ("ASI02",),
    "filesystem": ("ASI02",),
    "sql": ("ASI02",),
}
