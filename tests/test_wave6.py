import json
import subprocess
import sys
from textwrap import dedent

import pytest

from mcp_vulnlab.garak_probes.mcp_tool_shadowing import (
    metadata_report,
    score_metadata,
    snapshot_metadata,
)
from mcp_vulnlab.report import report
from mcp_vulnlab.static_audit import audit_js, audit_python


@pytest.mark.parametrize(("source", "rule", "line"), [
    ("""
        def ignored(value):
            return '/sample'
        def read(path):
            return open(path)
        @mcp.tool()
        def sample(value):
            return read(ignored(value))
    """, None, None),
    ("""
        def target(*, path):
            return open(path)
        def relay(path, /):
            return target(path=path)
        @mcp.tool()
        def sample(path):
            return relay(path)
    """, "filesystem", 2),
    ("""
        async def prepare(value):
            return f'SELECT label FROM sample WHERE id = {value}'
        @mcp.tool()
        async def sample(value):
            query = await prepare(value)
            return db.execute(query)
    """, "sql", 6),
    ("""
        def relay(*values):
            return values[0]
        @mcp.tool
        def sample(path):
            return open(relay(path))
    """, "filesystem", 5),
    ("""
        def relay(**values):
            return values['url']
        @mcp.call_tool()
        def sample(url):
            return urllib3.request('GET', relay(url=url))
    """, "network", 5),
    ("""
        def a(path, count):
            return b(path, count - 1)
        def b(path, count):
            return a(path, count - 1) if count else path
        @mcp.tool()
        def sample(path):
            return open(a(path, 1))
    """, "filesystem", 7),
    ("""
        @mcp.tool()
        async def sample(url):
            from aiohttp import ClientSession
            async with ClientSession() as client:
                return await client.get(url)
    """, "network", 5),
    ("""
        @mcp.tool()
        def sample(url):
            return urllib3.PoolManager().request('GET', url=url)
    """, "network", 3),
    ("""
        @mcp.tool()
        def sample(value):
            return urllib3.PoolManager().request('POST', 'https://example.invalid', body=value)
    """, None, None),
    ("""
        @mcp.tool()
        def sample(value):
            return db.execute('SELECT label FROM sample WHERE id = ?', (value,))
    """, None, None),
    ("""
        @mcp.tool()
        def sample(value):
            query = 'SELECT label FROM sample WHERE id = {}'
            return db.execute(query.format(value))
    """, "sql", 4),
    ("""
        from yaml import CSafeLoader as Safe
        @mcp.tool()
        def sample(value):
            return yaml.load(value, Safe)
    """, None, None),
])
def test_python_wave6(source, rule, line):
    findings = audit_python(dedent(source).lstrip(), "sample.py")
    assert [(item.rule, item.line) for item in findings] == ([(rule, line)] if rule else [])


@pytest.mark.parametrize(("statement", "expected"), [
    ("return exec(`sample ${value}`);", {"command"}),
    ("return exec(`sample`);", set()),
    ("return exec('sample ' + 'fixed');", set()),
    ("return spawn('sample', [value], {shell: true});", {"command"}),
    ("return spawn('sample', [value], {shell: false});", set()),
    ("return spawn('sample', {shell: true});", set()),
    ("return fs.promises.writeFile(value, 'sample');", {"filesystem"}),
    ("return fs.promises.writeFile('sample.txt', value);", set()),
    ("return axios({url: '/sample', baseURL: value});", {"network"}),
    ("return axios.post('https://example.invalid', value);", set()),
    ("return db.query(`SELECT label FROM sample WHERE id = ${value}`);", {"sql"}),
    ("const query = `SELECT label FROM sample WHERE id = ${value}`; return db.query(query);", {"sql"}),
    ("return db.query({text: 'SELECT label FROM sample WHERE id = $1', values: [value]});", set()),
    ("// exec(value);\n return 0;", set()),
    ("return 'fetch(value)';", set()),
])
def test_javascript_wave6(statement, expected):
    source = f"server.tool('sample', async (value) => {{\n{statement}\n}});"
    assert {item.rule for item in audit_js(source, "sample.js")} == expected


@pytest.mark.parametrize("value", [r"Sample\u200B label", r"Sample\u{202E} label", "Sample\u2066 label"])
def test_unicode_in_source_schema(value):
    source = (
        "server.registerTool('sample', {inputSchema: "
        f"{{label: z.string().describe('{value}')}}}}, callback);"
    )
    assert {item.rule for item in audit_js(source, "sample.ts")} == {"hidden-unicode"}


def test_unicode_in_comments_and_escaped_backslash():
    source = r"server.registerTool('sample', {description: 'Literal \\u200B'}, callback);"
    assert audit_js(source + "\n// \u202e", "sample.ts") == []


def test_snapshot_canonical_serialization_and_schema_drift():
    baseline = snapshot_metadata([{"name": "Sample", "inputSchema": {"type": "object"}}])
    assert baseline == {
        "version": 1, "algorithm": "sha256",
        "tools": {"sample": baseline["tools"]["sample"]},
    }
    assert len(baseline["tools"]["sample"]) == 64
    assert score_metadata(
        [{"inputSchema": {"type": "object"}, "name": "Sample"}], baseline=baseline
    )[0]["reasons"] == []
    assert score_metadata(
        [{"name": "Sample", "inputSchema": {"type": "string"}}], baseline=baseline
    )[0]["reasons"] == ["metadata-drift"]


def test_snapshot_detects_addition_and_removal():
    scores = score_metadata([{"name": "other"}], baseline=snapshot_metadata([{"name": "sample"}]))
    assert [(row["name"], row["reasons"]) for row in scores] == [
        ("other", ["metadata-added"]), ("sample", ["metadata-removed"]),
    ]


@pytest.mark.parametrize("snapshot", [
    {},
    {"version": 2, "algorithm": "sha256", "tools": {}},
    {"version": 1, "algorithm": "sha1", "tools": {}},
    {"version": 1, "algorithm": "sha256", "tools": {"sample": "wrong"}},
])
def test_invalid_snapshot(snapshot):
    with pytest.raises(ValueError, match="invalid SHA-256 metadata snapshot"):
        score_metadata([], baseline=snapshot)


def test_metadata_bidi_and_homoglyph_normalization():
    scores = score_metadata([{"name": "sample"}, {"name": "sаm\u202eple"}])
    assert [row["reasons"] for row in scores] == [
        ["duplicate-tool-name"], ["hidden-unicode", "duplicate-tool-name"],
    ]


@pytest.mark.parametrize("output_format", ["json", "sarif"])
def test_metadata_cli_with_snapshot(tmp_path, output_format):
    tools = tmp_path / "tools.json"
    tools.write_text('[{"name":"sample","description":"Original label."}]')
    cli = [sys.executable, "-m", "mcp_vulnlab.garak_probes.mcp_tool_shadowing", str(tools)]
    baseline = tmp_path / "baseline.json"
    baseline.write_text(subprocess.check_output([*cli, "--snapshot"], text=True))
    tools.write_text('[{"name":"sample","description":"Updated label."}]')
    process = subprocess.run(
        [*cli, "--baseline", str(baseline), "--format", output_format],
        capture_output=True, check=True, text=True,
    )
    result = json.loads(process.stdout)
    if output_format == "json":
        assert result["scores"][0]["owaspAgentic"] == ["ASI04"]
        assert len(result["owaspAgenticCategories"]) == 10
        assert result["advisories"][0]["rule"] == "metadata-drift"
    else:
        run = result["runs"][0]
        assert result["version"] == "2.1.0"
        assert len(run["taxonomies"][0]["taxa"]) == 10
        category, = run["results"][0]["taxa"]
        assert run["taxonomies"][0]["taxa"][category["index"]]["id"] == "ASI04"


def test_source_and_metadata_reports_share_taxonomy():
    findings = audit_python("@mcp.tool()\ndef sample(value):\n    return os.system(value)", "sample.py")
    source = report(findings, "json")
    metadata = metadata_report([], "tools.json", "json")
    assert source["owaspAgenticCategories"] == metadata["owaspAgenticCategories"]
    assert source["advisories"][0]["owaspAgentic"] == ["ASI02", "ASI05"]
