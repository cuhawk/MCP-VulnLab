"""Labeled inert source and metadata fixtures. Source strings are never executed."""

from dataclasses import dataclass
from textwrap import indent

from mcp_vulnlab.garak_probes.mcp_tool_shadowing import score_metadata, snapshot_metadata
from mcp_vulnlab.static_audit import audit_js, audit_python


@dataclass(frozen=True)
class Fixture:
    name: str
    kind: str
    content: str | list
    expected: frozenset
    baseline: dict | None = None

    def scan(self):
        if self.kind == "metadata":
            return {reason for row in score_metadata(self.content, baseline=self.baseline)
                    for reason in row["reasons"]}
        scanner = audit_python if self.kind == "py" else audit_js
        return {item.rule for item in scanner(self.content, f"{self.name}.{self.kind}")}


PYTHON = [
    ("helper-sink", "network",
     "def send(url):\n    return urllib3.request('GET', url)\n",
     "return send(value)", "return send('https://example.invalid')"),
    ("helper-return", "filesystem",
     "def get_path(unused, *, path):\n    return path\n",
     "return open(get_path(None, path=value))", "return open(get_path(value, path='sample.txt'))"),
    ("helper-chain", "command",
     "def outer(x):\n    return inner(x)\ndef inner(x):\n    return x\n",
     "return pty.spawn(outer(value))", "return pty.spawn(outer('/usr/bin/true'))"),
    ("recursive", "filesystem",
     "def loop(x, count):\n    return loop(x, count - 1) if count else x\n",
     "return open(loop(value, 2))", "return open(loop('sample.txt', 2))"),
    ("urllib-pool", "network", "import urllib3 as u\n",
     "pool = u.PoolManager()\nreturn pool.request('GET', value)",
     "pool = u.PoolManager()\nreturn pool.request('POST', 'https://example.invalid', body=value)"),
    ("http-client-host", "network", "from http.client import HTTPSConnection as Connection\n",
     "return Connection(value)", "return Connection('example.invalid')"),
    ("http-client-request", "network", "import http.client\n",
     "conn = http.client.HTTPConnection('example.invalid')\nreturn conn.request('GET', value)",
     "conn = http.client.HTTPConnection('example.invalid')\nreturn conn.request('POST', '/', body=value)"),
    ("aiohttp-session", "network", "import aiohttp\n",
     "async with aiohttp.ClientSession() as client:\n    return await client.get(value)",
     "async with aiohttp.ClientSession() as client:\n    return await client.post('https://example.invalid', data=value)"),
    ("websockets", "network", "from websockets.asyncio.client import connect\n",
     "return connect(value)", "return connect('wss://example.invalid')"),
    ("execv", "command", "import os\n",
     "return os.execv(value, ['sample'])", "return os.execv('/usr/bin/true', ['true'])"),
    ("execvpe", "command", "from os import execvpe as launch\n",
     "return launch(value, ['sample'], {})", "return launch('/usr/bin/true', ['true'], {})"),
    ("shutil-copy", "filesystem", "import shutil as files\n",
     "return files.copy('sample.txt', value)", "return files.copy('sample.txt', 'copy.txt')"),
    ("shutil-unpack", "filesystem", "from shutil import unpack_archive\n",
     "return unpack_archive(value)", "return unpack_archive('sample.zip', 'sample')"),
    ("yaml-loader", "deserialization", "from yaml import load, SafeLoader, Loader\n",
     "return load(value, Loader=Loader)", "return load(value, Loader=SafeLoader)"),
    ("sql-fstring", "sql", "",
     "return cursor.execute(f'SELECT label FROM sample WHERE id = {value}')",
     "return cursor.execute('SELECT label FROM sample WHERE id = ?', (value,))"),
    ("sql-percent", "sql", "",
     "query = 'SELECT label FROM sample WHERE id = %s' % value\nreturn cursor.execute(query)",
     "query = 'SELECT label FROM sample WHERE id = %s'\nreturn cursor.execute(query, (value,))"),
    ("sql-format", "sql", "QUERY = 'SELECT label FROM sample WHERE id = {}'\n",
     "return cursor.execute(QUERY.format(value))",
     "return cursor.execute('SELECT label FROM sample WHERE id = ?', (value,))"),
    ("sql-helper", "sql", "def execute(query):\n    return cursor.execute(query)\n",
     "return execute('SELECT label FROM sample WHERE id = ' + value)",
     "return execute('SELECT label FROM sample')"),
]

TYPESCRIPT = [
    ("exec-template", "command", "import {exec as run} from 'node:child_process';",
     "return run(`sample ${value}`);", "return run(`sample --version`);"),
    ("exec-sync", "command", "import * as cp from 'node:child_process';",
     "return cp.execSync(value);", "return cp.execSync('sample --version');"),
    ("spawn-shell", "command", "import {spawn} from 'child_process';",
     "return spawn('sample', [value], {\n  shell: true\n});",
     "return spawn('sample', [value], {shell: false});"),
    ("spawn-options", "command", "const {spawn: start} = require('node:child_process');",
     "return start(`sample-${value}`, {shell: true});",
     "return start('sample', {shell: true});"),
    ("fs-promises", "filesystem", "import fs from 'node:fs';",
     "return fs.promises.readFile(`samples/${value}`);",
     "return fs.promises.readFile('samples/label.txt');"),
    ("fs-module", "filesystem", "import {writeFile as save} from 'node:fs/promises';",
     "return save(value, 'sample');", "return save('sample.txt', value);"),
    ("fs-copy", "filesystem", "const fsp = require('node:fs/promises');",
     "return fsp.copyFile('sample.txt', value);", "return fsp.copyFile('sample.txt', 'copy.txt');"),
    ("fetch-template", "network", "",
     "return fetch(`https://example.invalid/${value}`);",
     "return fetch('https://example.invalid', {method: 'POST', body: value});"),
    ("axios-get", "network", "import http from 'axios';",
     "return http.get(`https://example.invalid/${value}`);",
     "return http.get('https://example.invalid', {params: {value}});"),
    ("axios-config", "network", "import axios from 'axios';",
     "return axios.request({url: value});",
     "return axios.request({url: 'https://example.invalid', data: value});"),
    ("sql-template", "sql", "",
     "return db.query(`SELECT label FROM sample WHERE id = ${value}`);",
     "return db.query('SELECT label FROM sample WHERE id = $1', [value]);"),
    ("sql-config", "sql", "",
     "return db.query({text: 'SELECT label FROM sample WHERE id = ' + value});",
     "return db.query({text: 'SELECT label FROM sample WHERE id = $1', values: [value]});"),
]

METADATA = [
    ("zero-width", [{"name": "sample", "description": "Sample\u200b label."}],
     [{"name": "sample", "description": "Sample label."}], {"hidden-unicode"}, None),
    ("bidi-title", [{"name": "sample", "annotations": {"title": "Sample\u202e label"}}],
     [{"name": "sample", "annotations": {"title": "Sample label"}}], {"hidden-unicode"}, None),
    ("lookalike", [{"name": "lookup"}, {"name": "lооkup"}],
     [{"name": "lookup"}, {"name": "list"}], {"duplicate-tool-name"}, None),
    ("schema-drift", [{"name": "sample", "inputSchema": {"type": "string"}}],
     [{"name": "sample", "inputSchema": {"type": "object"}}], {"metadata-drift"},
     [{"name": "sample", "inputSchema": {"type": "object"}}]),
    ("replacement", [{"name": "other"}], [{"name": "sample"}],
     {"metadata-added", "metadata-removed"}, [{"name": "sample"}]),
]


def fixtures():
    for name, rule, prelude, review, clean in PYTHON:
        for label, body, expected in [("review", review, {rule}), ("clean", clean, set())]:
            content = prelude + "\n@mcp.tool()\nasync def sample(value):\n" + indent(body, "    ")
            yield Fixture(f"{name}-{label}", "py", content, frozenset(expected))
    for name, rule, prelude, review, clean in TYPESCRIPT:
        for label, body, expected in [("review", review, {rule}), ("clean", clean, set())]:
            content = (
                f"{prelude}\nserver.registerTool('sample', {{description: 'Read a label.'}},\n"
                f"  async ({{value}}: {{value: string}}) => {{\n{indent(body, '    ')}\n  }});\n"
            )
            yield Fixture(f"{name}-{label}", "ts", content, frozenset(expected))
    for syntax, escaped in [("zero-width", r"\u200B"), ("bidi", "\u202e")]:
        for label, marker in [("review", escaped), ("clean", "")]:
            content = f"server.registerTool('sample', {{description: 'Sample{marker} label'}});"
            expected = {"hidden-unicode"} if marker else set()
            yield Fixture(f"ts-{syntax}-{label}", "ts", content, frozenset(expected))
    for name, review, clean, expected, trusted in METADATA:
        baseline = snapshot_metadata(trusted) if trusted else None
        yield Fixture(f"metadata-{name}-review", "metadata", review, frozenset(expected), baseline)
        yield Fixture(f"metadata-{name}-clean", "metadata", clean, frozenset(), baseline)
