"""Offline source review for MCP tool declarations and security-sensitive sinks."""

import ast
import re
from itertools import chain
from dataclasses import dataclass
from pathlib import Path

INSTRUCTION = re.compile(r"<\s*(?:important|system|developer)\b", re.IGNORECASE)
PYTHON_SINKS = {
    "os.system": "command",
    "eval": "command",
    "exec": "command",
    "open": "filesystem",
    "pathlib.Path": "filesystem",
    "requests.get": "network",
    "requests.post": "network",
    "requests.request": "network",
    "httpx.get": "network",
    "httpx.post": "network",
    "httpx.request": "network",
    "pickle.load": "deserialization",
    "pickle.loads": "deserialization",
}
PYTHON_SINKS.update({
    **{f"os.{name}": "command" for name in (
        "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe"
    )},
    "pty.spawn": "command",
    **{f"shutil.{name}": "filesystem" for name in (
        "copy", "copy2", "copyfile", "copyfileobj", "copymode", "copystat", "copytree",
        "move", "rmtree", "chown", "make_archive", "unpack_archive"
    )},
    **{name: "network" for name in (
        "urllib3.request", "urllib3.PoolManager.request", "urllib3.ProxyManager",
        "urllib3.ProxyManager.request", "urllib3.HTTPConnectionPool", "urllib3.HTTPSConnectionPool",
        "urllib3.HTTPConnectionPool.request", "urllib3.HTTPSConnectionPool.request", "http.client.HTTPConnection",
        "http.client.HTTPSConnection", "http.client.HTTPConnection.request",
        "http.client.HTTPSConnection.request", "aiohttp.request",
        "websockets.connect", "websockets.client.connect", "websockets.asyncio.client.connect",
        "websockets.sync.client.connect", "websockets.legacy.client.connect",
    )},
    **{f"aiohttp.ClientSession.{name}": "network" for name in (
        "request", "get", "post", "put", "patch", "delete", "head", "options", "ws_connect"
    )},
})
REQUEST_METHOD_FIRST = {
    "urllib3.request", "urllib3.PoolManager.request", "urllib3.ProxyManager.request",
    "urllib3.HTTPConnectionPool.request", "urllib3.HTTPSConnectionPool.request",
    "http.client.HTTPConnection.request", "http.client.HTTPSConnection.request",
    "aiohttp.request", "aiohttp.ClientSession.request", "requests.request", "httpx.request",
}
URL_FIRST = {
    "requests.get", "requests.post", "httpx.get", "httpx.post",
    *(name for name in PYTHON_SINKS if name.startswith(("aiohttp.ClientSession.", "websockets."))
      and name not in REQUEST_METHOD_FIRST),
}

SUBPROCESS = {"subprocess.run", "subprocess.call", "subprocess.Popen",
              "subprocess.check_output", "subprocess.check_call"}


@dataclass(frozen=True, order=True)
class Advisory:
    path: str
    line: int
    rule: str
    message: str


def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{dotted(node.value)}.{node.attr}"
    return ""


def function_nodes(body):
    pending = list(reversed(body))
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield node
        pending.extend(reversed(list(ast.iter_child_nodes(node))))


def parameter_names(function):
    args = function.args
    return [item.arg for item in chain(args.posonlyargs, args.args, args.kwonlyargs,
                                     filter(None, (args.vararg, args.kwarg)))]


def bind_inputs(function, call, reference):
    args = function.args
    positional = [item.arg for item in (*args.posonlyargs, *args.args)]
    keyword = {item.arg for item in (*args.args, *args.kwonlyargs)}
    names = set()
    for index, value in enumerate(call.args):
        if isinstance(value, ast.Starred):
            if any(reference(arg) for arg in call.args[index:]):
                names.update(positional[index:])
                if args.vararg:
                    names.add(args.vararg.arg)
            break
        if reference(value):
            if index < len(positional):
                names.add(positional[index])
            elif args.vararg:
                names.add(args.vararg.arg)
    for item in call.keywords:
        if not reference(item.value):
            continue
        if item.arg is None:
            names.update(keyword)
            if args.kwarg:
                names.add(args.kwarg.arg)
        elif item.arg in keyword:
            names.add(item.arg)
        elif args.kwarg:
            names.add(args.kwarg.arg)
    return frozenset(names)


def audit_python(source, path):
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        return [Advisory(path, exc.lineno or 1, "parse-error", "Python source could not be parsed.")]

    functions = (ast.FunctionDef, ast.AsyncFunctionDef)
    helpers = {node.name: node for node in tree.body if isinstance(node, functions)}
    findings = set()
    summaries = {}

    def analyze(node, inputs, formatted_inputs):
        statements = list(function_nodes(node.body))
        aliases = {}
        receivers = {}
        for item in chain(tree.body, statements):
            if isinstance(item, ast.Import):
                aliases.update((alias.asname, alias.name) for alias in item.names if alias.asname)
            elif isinstance(item, ast.ImportFrom) and item.module and not item.level:
                aliases.update((alias.asname or alias.name, f"{item.module}.{alias.name}")
                               for alias in item.names)

        def resolve(expression):
            if isinstance(expression, ast.Attribute):
                if isinstance(expression.value, ast.Call):
                    prefix = resolve(expression.value.func)
                else:
                    prefix = resolve(expression.value)
                return f"{prefix}.{expression.attr}"
            name = dotted(expression)
            return receivers.get(name, aliases.get(name, name))

        for item in tree.body:
            if isinstance(item, ast.Assign) and isinstance(item.value, ast.Call):
                constructor = resolve(item.value.func)
                if any(sink.startswith(constructor + ".") for sink in PYTHON_SINKS):
                    receivers.update((target.id, constructor) for target in item.targets
                                     if isinstance(target, ast.Name))

        def helper_summary(call):
            if not isinstance(call.func, ast.Name) or call.func.id not in helpers:
                return None
            helper = helpers[call.func.id]
            key = (helper, bind_inputs(helper, call, reference),
                   bind_inputs(helper, call, formatted))
            return summaries.setdefault(key, (False, False))

        def reference(expression):
            if isinstance(expression, ast.Name):
                return expression.id in names
            if isinstance(expression, ast.Call):
                summary = helper_summary(expression)
                if summary is not None:
                    return summary[0]
                if resolve(expression.func) in {"int", "float", "bool"}:
                    return False
            return any(reference(child) for child in ast.iter_child_nodes(expression))

        def formatted(expression):
            if isinstance(expression, ast.Name):
                return expression.id in queries
            if isinstance(expression, ast.Await):
                return formatted(expression.value)
            if isinstance(expression, ast.Call):
                summary = helper_summary(expression)
                if summary is not None:
                    return summary[1]
                return isinstance(expression.func, ast.Attribute) and (
                    expression.func.attr in {"format", "format_map"}
                    and string_expression(expression.func.value)
                    and reference(expression)
                )
            if isinstance(expression, ast.JoinedStr):
                return reference(expression)
            if isinstance(expression, ast.BinOp) and isinstance(expression.op, (ast.Add, ast.Mod)):
                return formatted(expression.left) or formatted(expression.right) or (
                    any(string_expression(side) for side in (expression.left, expression.right)) and reference(expression)
                )
            return False

        def string_expression(expression):
            return (
                isinstance(expression, ast.Constant) and isinstance(expression.value, str)
                or isinstance(expression, ast.JoinedStr)
                or isinstance(expression, ast.Name) and expression.id in literal_strings
            )

        names = set(inputs)
        queries = set(formatted_inputs)
        assignments = []
        literal_strings = {
            target.id for item in tree.body if isinstance(item, ast.Assign)
            and isinstance(item.value, ast.Constant) and isinstance(item.value.value, str)
            for target in item.targets if isinstance(target, ast.Name)
        }
        for item in statements:
            if isinstance(item, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                targets = item.targets if isinstance(item, ast.Assign) else [item.target]
                if item.value is not None:
                    assignments.extend((target.id, item.value) for target in targets
                                       if isinstance(target, ast.Name))
            elif isinstance(item, (ast.With, ast.AsyncWith)):
                assignments.extend((part.optional_vars.id, part.context_expr) for part in item.items
                                   if isinstance(part.optional_vars, ast.Name))

        for _ in range(len(assignments) + 1):
            before = (len(names), len(queries), len(receivers), len(literal_strings))
            for target, value in assignments:
                if string_expression(value):
                    literal_strings.add(target)
                if reference(value):
                    names.add(target)
                if formatted(value):
                    queries.add(target)
                if isinstance(value, ast.Call):
                    constructor = resolve(value.func)
                    if any(sink.startswith(constructor + ".") for sink in PYTHON_SINKS):
                        receivers.setdefault(target, constructor)
                elif isinstance(value, ast.Name) and value.id in receivers:
                    receivers.setdefault(target, receivers[value.id])
            if before == (len(names), len(queries), len(receivers), len(literal_strings)):
                break

        results = [item.value for item in statements if isinstance(item, ast.Return) and item.value]
        for call in (item for item in statements if isinstance(item, ast.Call)):
            if helper_summary(call) is not None:
                continue
            function = resolve(call.func)
            keywords = {item.arg: item.value for item in call.keywords}
            arguments = [*call.args, *keywords.values()]
            if function in SUBPROCESS:
                shell = keywords.get("shell")
                rule = "command" if shell is not None and not (
                    isinstance(shell, ast.Constant) and shell.value is False
                ) else None
            elif function == "yaml.load":
                loader = keywords.get("Loader", call.args[1] if len(call.args) > 1 else None)
                rule = None if resolve(loader) in {"yaml.SafeLoader", "yaml.CSafeLoader"} else "deserialization"
                arguments = call.args[:1] or ([keywords["stream"]] if "stream" in keywords else [])
            else:
                rule = PYTHON_SINKS.get(function)
            if function in REQUEST_METHOD_FIRST:
                arguments = call.args[1:2] or [keywords[key] for key in ("url", "uri") if key in keywords]
            elif function in URL_FIRST:
                arguments = call.args[:1] or [keywords[key] for key in ("url", "uri", "str_or_url") if key in keywords]
            if rule and any(reference(value) for value in arguments):
                findings.add(Advisory(path, call.lineno, rule,
                                      f"Review tool-controlled input reaching {function}."))
            if isinstance(call.func, ast.Attribute) and call.func.attr in {
                "execute", "executemany", "executescript"
            }:
                query = call.args[0] if call.args else keywords.get("sql", keywords.get("query"))
                if formatted(query):
                    findings.add(Advisory(path, call.lineno, "sql",
                                          "Review tool-controlled SQL string formatting."))
        return any(reference(value) for value in results), any(formatted(value) for value in results)

    for node in ast.walk(tree):
        if not isinstance(node, functions):
            continue
        decorators = [dotted(item.func if isinstance(item, ast.Call) else item)
                      for item in node.decorator_list]
        if not any(item.endswith((".tool", ".call_tool")) for item in decorators):
            continue
        if INSTRUCTION.search(ast.get_docstring(node) or ""):
            findings.add(Advisory(path, node.body[0].lineno, "schema-shadowing",
                                  "Review instructional markup in the tool description."))
        inputs = frozenset(parameter_names(node)) - {"self", "cls"}
        summaries[node, inputs, frozenset()] = (False, False)

    # Each call context has two monotone return facts. New contexts start empty,
    # so recursive calls converge without recursing through function bodies.
    while True:
        previous = summaries.copy()
        for key, old in previous.items():
            result = analyze(*key)
            summaries[key] = tuple(a or b for a, b in zip(old, result, strict=True))
        if previous == summaries:
            return sorted(findings)


def audit_js(source, path):
    from .js_audit import audit_js as scan

    return scan(source, path)


def audit_path(path: Path):
    scanners = {".py": audit_python, ".js": audit_js, ".ts": audit_js,
                ".tsx": audit_js, ".mjs": audit_js, ".cjs": audit_js, ".mts": audit_js, ".cts": audit_js}
    if path.is_file():
        files = [path]
        root = path.parent
    else:
        files = sorted(path.rglob("*"))
        root = path
    output = []
    for file in files:
        relative = file.relative_to(root)
        if (file.is_symlink() or any(part.startswith(".") or part == "node_modules"
                                     for part in relative.parts)
                or file.suffix not in scanners or not file.is_file()):
            continue
        output.extend(scanners[file.suffix](file.read_text(), relative.as_posix()))
    return sorted(output)
