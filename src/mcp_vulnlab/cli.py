import argparse
import json
from pathlib import Path

from .report import report
from .static_audit import audit_path


def main():
    parser = argparse.ArgumentParser(prog="mcp-vulnlab")
    parser.add_argument("path", type=Path)
    parser.add_argument("--format", choices=["json", "sarif"], default="json")
    args = parser.parse_args()
    if not args.path.exists():
        parser.error("input path does not exist")
    try:
        print(json.dumps(report(audit_path(args.path), args.format), indent=2))
    except (OSError, UnicodeError) as exc:
        parser.exit(2, f"mcp-vulnlab: {exc}\n")
