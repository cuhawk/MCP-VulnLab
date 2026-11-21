"""Score saved MCP tool metadata locally, with an optional garak adapter."""

import argparse
import hashlib
import json
import re
from pathlib import Path

from mcp_vulnlab.agentic import RULE_CATEGORIES
from mcp_vulnlab.metadata_unicode import canonical, contains_hidden
from mcp_vulnlab.report import report
from mcp_vulnlab.static_audit import Advisory, INSTRUCTION

_OVERRIDE = re.compile(
    r"\b(?:ignore|disregard|override|forget)\s+(?:all\s+)?"
    r"(?:(?:the|any|your)\s+)?(?:(?:previous|prior|earlier|system|developer)\s+)+"
    r"(?:instructions?|prompts?|rules?|messages?)\b"
)


def fingerprint(tool):
    payload = json.dumps(tool, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                         allow_nan=False)
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


def snapshot_metadata(tools: list[dict]) -> dict:
    """Hash complete records, ignoring JSON object key order."""
    if not isinstance(tools, list):
        raise ValueError("tool metadata must be a JSON array")
    records = {}
    for tool in tools:
        name = canonical(tool["name"])
        if name in records:
            raise ValueError("baseline tool names must be unique")
        records[name] = fingerprint(tool)
    return {"version": 1, "algorithm": "sha256", "tools": records}


def score_metadata(
    tools: list[dict], *, baseline: list[dict] | dict | None = None
) -> list[dict]:
    """Review saved metadata against a trusted legacy array or a SHA-256 snapshot."""
    if not isinstance(tools, list):
        raise ValueError("tool metadata and legacy baselines must be JSON arrays")
    trusted = {}
    hashes = None
    if isinstance(baseline, dict):
        hashes = baseline.get("tools")
        if (baseline.get("version") != 1 or baseline.get("algorithm") != "sha256"
                or not isinstance(hashes, dict) or any(
                    not isinstance(name, str) or canonical(name) != name
                    or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
                    for name, digest in hashes.items()
                )):
            raise ValueError("invalid SHA-256 metadata snapshot")
    elif baseline is not None:
        snapshot_metadata(baseline)
        trusted = {canonical(tool["name"]): canonical(tool.get("description", ""))
                   for tool in baseline}

    names = [canonical(tool["name"]) for tool in tools]
    seen = set()
    duplicates = set()
    for name in names:
        if name in seen:
            duplicates.add(name)
        seen.add(name)

    scores = []
    for tool, name in zip(tools, names, strict=True):
        description = canonical(tool.get("description", ""))
        reasons = []
        if _OVERRIDE.search(description) or INSTRUCTION.search(description):
            reasons.append("instruction-override")
        if contains_hidden(tool):
            reasons.append("hidden-unicode")
        if name in duplicates:
            reasons.append("duplicate-tool-name")
        if name in trusted and description != trusted[name]:
            reasons.append("description-changed")
        if hashes is not None:
            if name not in hashes:
                reasons.append("metadata-added")
            elif fingerprint(tool) != hashes[name]:
                reasons.append("metadata-drift")
        scores.append({"name": tool["name"], "score": float(bool(reasons)), "reasons": reasons})
    if hashes is not None:
        scores.extend({"name": name, "score": 1.0, "reasons": ["metadata-removed"]}
                      for name in sorted(hashes.keys() - seen))
    return scores


def tagged_score(score):
    categories = {category for reason in score["reasons"] for category in RULE_CATEGORIES[reason]}
    return score | {"owaspAgentic": sorted(categories)}


def metadata_report(scores, path, output_format):
    # Records have no stable source-line mapping after JSON decoding.
    advisories = [Advisory(path, 1, reason, f"Review tool metadata for {score['name']!r}: {reason}.")
                  for score in scores for reason in score["reasons"]]
    result = report(advisories, output_format)
    if output_format == "json":
        result["scores"] = [tagged_score(score) for score in scores]
    return result


try:
    from garak.attempt import Message
    from garak.probes.base import Probe
except ModuleNotFoundError as exc:
    if exc.name != "garak":
        raise
else:
    class MCPToolShadowing(Probe):
        """Review configured metadata without invoking the supplied generator."""

        goal = "flag instruction overrides and tool-description shadowing in saved metadata"
        lang = "*"
        primary_detector = "always.Passthru"
        prompts = []
        DEFAULT_PARAMS = Probe.DEFAULT_PARAMS | {"tools": [], "baseline": []}

        def probe(self, generator):
            attempts = []
            for index, result in enumerate(score_metadata(self.tools, baseline=self.baseline)):
                attempt = self._mint_attempt("Review saved MCP tool metadata.", seq=index)
                attempt.outputs = [Message(text=json.dumps(tagged_score(result)))]
                attempt.detector_results["always.Passthru"] = [result["score"]]
                attempts.append(attempt)
            return attempts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tools", type=Path, help="JSON array of MCP tool metadata")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--baseline", type=Path, help="trusted JSON array or SHA-256 snapshot")
    mode.add_argument("--snapshot", action="store_true", help="emit a SHA-256 snapshot")
    parser.add_argument("--format", choices=["json", "sarif"])
    args = parser.parse_args()
    try:
        tools = json.loads(args.tools.read_text(encoding="utf-8"))
        if args.snapshot:
            print(json.dumps(snapshot_metadata(tools), indent=2, sort_keys=True))
            return
        baseline = (
            json.loads(args.baseline.read_text(encoding="utf-8")) if args.baseline else None
        )
        scores = score_metadata(tools, baseline=baseline)
        output = metadata_report(scores, args.tools.name, args.format) if args.format else scores
        print(json.dumps(output, indent=2))
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
