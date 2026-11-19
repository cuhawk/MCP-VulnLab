"""Serialize local source-review findings to JSON or SARIF."""

from dataclasses import asdict
from urllib.parse import quote


def report(findings, output_format):
    if output_format == "json":
        return {"advisories": [asdict(item) for item in findings]}
    if output_format != "sarif":
        raise ValueError("unknown report format")
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "MCP-VulnLab", "rules": [
                {"id": rule} for rule in sorted({item.rule for item in findings})
            ]}},
            "results": [{
                "ruleId": item.rule,
                "level": "warning",
                "message": {"text": item.message},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": quote(item.path)},
                    "region": {"startLine": item.line},
                }}],
            } for item in findings],
        }],
    }
