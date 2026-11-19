"""Score saved MCP tool metadata locally, with an optional garak adapter."""

import argparse
import json
import re
import unicodedata
from pathlib import Path

from mcp_vulnlab.static_audit import INSTRUCTION

_OVERRIDE = re.compile(
    r"\b(?:ignore|disregard|override|forget)\s+(?:all\s+)?"
    r"(?:(?:the|any|your)\s+)?(?:(?:previous|prior|earlier|system|developer)\s+)+"
    r"(?:instructions?|prompts?|rules?|messages?)\b"
)


def _canonical(text: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def score_metadata(
    tools: list[dict], *, baseline: list[dict] | None = None
) -> list[dict]:
    """Return one binary score and a list of review reasons per tool.

    The optional trusted baseline detects description drift under a known name.
    Duplicate normalized names are flagged in every conflicting record.
    """
    if not isinstance(tools, list) or (baseline is not None and not isinstance(baseline, list)):
        raise ValueError("tool metadata and baseline must be JSON arrays")
    trusted = {}
    for tool in baseline or []:
        name = _canonical(tool["name"])
        if name in trusted:
            raise ValueError("baseline tool names must be unique")
        trusted[name] = _canonical(tool.get("description", ""))

    names = [_canonical(tool["name"]) for tool in tools]
    seen = set()
    duplicates = set()
    for name in names:
        if name in seen:
            duplicates.add(name)
        seen.add(name)

    scores = []
    for tool, name in zip(tools, names, strict=True):
        description = _canonical(tool.get("description", ""))
        reasons = []
        if _OVERRIDE.search(description) or INSTRUCTION.search(description):
            reasons.append("instruction-override")
        if name in duplicates:
            reasons.append("duplicate-tool-name")
        if name in trusted and description != trusted[name]:
            reasons.append("description-changed")
        scores.append({"name": tool["name"], "score": float(bool(reasons)), "reasons": reasons})
    return scores


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
                attempt.outputs = [Message(text=json.dumps(result))]
                attempt.detector_results["always.Passthru"] = [result["score"]]
                attempts.append(attempt)
            return attempts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tools", type=Path, help="JSON array of MCP tool metadata")
    parser.add_argument("--baseline", type=Path, help="trusted JSON array to compare against")
    args = parser.parse_args()
    try:
        tools = json.loads(args.tools.read_text(encoding="utf-8"))
        baseline = (
            json.loads(args.baseline.read_text(encoding="utf-8")) if args.baseline else None
        )
        print(json.dumps(score_metadata(tools, baseline=baseline), indent=2))
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
