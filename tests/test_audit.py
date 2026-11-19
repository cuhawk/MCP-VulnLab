from textwrap import indent

import pytest

from mcp_vulnlab.report import report
from mcp_vulnlab.static_audit import audit_js, audit_path, audit_python


def findings(body, prelude=""):
    return audit_python(prelude + "\n@mcp.tool()\ndef tool(value):\n" +
                        indent(body, "    "), "tool.py")


@pytest.mark.parametrize(("body", "rule"), [
    ("return os.system(value)", "command"),
    ("return eval(value)", "command"),
    ("return exec(value)", "command"),
    ("return subprocess.run(value, shell=True)", "command"),
    ("return open(value)", "filesystem"),
    ("return pathlib.Path(value)", "filesystem"),
    ("return requests.get(value)", "network"),
    ("return httpx.post(url=value)", "network"),
    ("return yaml.load(value)", "deserialization"),
    ("return pickle.loads(value)", "deserialization"),
    ('"""<IMPORTANT> Review this description."""\nreturn 1', "schema-shadowing"),
    ("output = value\nreturn httpx.get(output)", "network"),
])
def test_python_findings(body, rule):
    assert {item.rule for item in findings(body)} == {rule}


@pytest.mark.parametrize("body", [
    'return open("fixed.txt")',
    'return requests.get("https://example.com")',
    'return subprocess.run(["echo", value], shell=False)',
    'return subprocess.run(["echo", value])',
    'return yaml.load(value, Loader=yaml.SafeLoader)',
    'return yaml.safe_load(value)',
    'return int(value)',
    'return open(str(int(value)))',
])
def test_safe_patterns(body):
    assert findings(body) == []


def test_alias():
    assert findings("return launch(value)", "from os import system as launch")[0].rule == "command"


def test_non_tool():
    assert audit_python("def helper(x):\n    return open(x)", "helper.py") == []


def test_invalid_python():
    assert audit_python("def broken(", "bad.py")[0].rule == "parse-error"


def test_js():
    assert audit_js("server.registerTool('lookup', async input => fetch(input.url))",
                    "server.ts")[0].rule == "network"


def test_js_non_tool():
    assert audit_js("fetch(input.url)", "http.ts") == []


def test_reports_and_paths(tmp_path):
    (tmp_path / "example.py").write_text("@mcp.tool()\ndef tool(x):\n    return open(x)")
    results = audit_path(tmp_path)
    assert report(results, "json")["advisories"][0]["path"] == "example.py"
    sarif = report(results, "sarif")
    assert sarif["version"] == "2.1.0"
    physical = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert physical["region"]["startLine"] == 3
