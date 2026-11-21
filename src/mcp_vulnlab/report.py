"""Serialize local source-review findings to JSON or SARIF."""

from dataclasses import asdict
from urllib.parse import quote

from .agentic import CATEGORIES, RULE_CATEGORIES


def report(findings, output_format):
    if output_format == "json":
        return {
            "advisories": [
                asdict(item) | {"owaspAgentic": list(RULE_CATEGORIES.get(item.rule, ()))}
                for item in findings
            ],
            "owaspAgenticCategories": CATEGORIES,
        }
    if output_format != "sarif":
        raise ValueError("unknown report format")
    findings = list(findings)
    rules = sorted({item.rule for item in findings})
    rule_indexes = {rule: index for index, rule in enumerate(rules)}
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "MCP-VulnLab", "rules": [
                {
                    "id": rule,
                    "relationships": [
                        {"target": {"id": category, "toolComponent": {"name": "OWASP Agentic Top 10", "index": 0}},
                         "kinds": ["relevant"]}
                        for category in RULE_CATEGORIES.get(rule, ())
                    ],
                } for rule in rules
            ]}},
            "taxonomies": [{
                "name": "OWASP Agentic Top 10",
                "version": "2026",
                "taxa": [
                    {"id": category, "shortDescription": {"text": title}}
                    for category, title in CATEGORIES.items()
                ],
            }],
            "results": [{
                "ruleId": item.rule,
                "ruleIndex": rule_indexes[item.rule],
                "level": "warning",
                "taxa": [
                    {"id": category, "toolComponent": {"name": "OWASP Agentic Top 10", "index": 0},
                     "index": list(CATEGORIES).index(category)}
                    for category in RULE_CATEGORIES.get(item.rule, ())
                ],
                "message": {"text": item.message},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": quote(item.path, safe="/")},
                    "region": {"startLine": item.line},
                }}],
            } for item in findings],
        }],
    }
