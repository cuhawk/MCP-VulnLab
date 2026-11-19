"""Offline source review for MCP tool declarations and security-sensitive sinks."""

import ast
import re
from dataclasses import dataclass
from pathlib import Path

INSTRUCTION = re.compile(r"<\s*(?:important|system|developer)\b", re.IGNORECASE)
JS_DECLARATION = re.compile(r"\b(?:registerTool|tool|setRequestHandler)\s*\(")
JS_REVIEW = (
    ("command", re.compile(r"\b(?:exec|execSync)\s*\(\s*[a-zA-Z_$]")),
    ("filesystem", re.compile(r"\b(?:readFile|writeFile|createReadStream)\s*\(\s*[a-zA-Z_$]")),
    ("network", re.compile(r"\bfetch\s*\(\s*[a-zA-Z_$]")),
    ("schema-shadowing", INSTRUCTION),
)
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


def input_reference(node, names):
    if isinstance(node, ast.Call) and dotted(node.func) in {"int", "float", "bool"}:
        return False
    if isinstance(node, ast.Name):
        return node.id in names
    if isinstance(node, ast.Constant):
        return False
    return any(input_reference(child, names) for child in ast.iter_child_nodes(node))


def audit_python(source, path):
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        return [Advisory(path, exc.lineno or 1, "parse-error", "Python source could not be parsed.")]
    aliases = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    def resolve(node):
        parts = dotted(node).split(".")
        return ".".join([aliases.get(parts[0], parts[0]), *parts[1:]])

    findings = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decorators = [dotted(item.func if isinstance(item, ast.Call) else item)
                      for item in node.decorator_list]
        if not any(item.endswith((".tool", ".call_tool")) for item in decorators):
            continue
        description = ast.get_docstring(node) or ""
        if INSTRUCTION.search(description):
            findings.add(Advisory(path, node.body[0].lineno, "schema-shadowing",
                                  "Review instructional markup in the tool description."))
        parameters = node.args
        names = {item.arg for item in [*parameters.posonlyargs, *parameters.args,
                                      *parameters.kwonlyargs] if item.arg not in {"self", "cls"}}
        names.update(item.arg for item in (parameters.vararg, parameters.kwarg) if item)
        statements = list(function_nodes(node.body))
        assignments = [item for item in statements
                       if isinstance(item, (ast.Assign, ast.AnnAssign, ast.NamedExpr))]
        for _ in range(len(assignments)):
            before = len(names)
            for assignment in assignments:
                if assignment.value is None or not input_reference(assignment.value, names):
                    continue
                targets = assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
                names.update(target.id for target in targets if isinstance(target, ast.Name))
            if before == len(names):
                break
        for call in statements:
            if not isinstance(call, ast.Call):
                continue
            function = resolve(call.func)
            keywords = {item.arg: item.value for item in call.keywords}
            if function in SUBPROCESS:
                shell = keywords.get("shell")
                rule = None if shell is None or (
                    isinstance(shell, ast.Constant) and shell.value is False
                ) else "command"
            elif function == "yaml.load":
                loader = keywords.get("Loader", call.args[1] if len(call.args) > 1 else None)
                rule = None if resolve(loader) in {"yaml.SafeLoader", "yaml.CSafeLoader"} else "deserialization"
            else:
                rule = PYTHON_SINKS.get(function)
            arguments = [*call.args, *keywords.values()]
            if rule and any(input_reference(value, names) for value in arguments):
                findings.add(Advisory(path, call.lineno, rule,
                                      f"Review tool-controlled input reaching {function}."))
    return sorted(findings)


def audit_js(source, path):
    if not JS_DECLARATION.search(source):
        return []
    return [
        Advisory(path, line, rule, "Review a security-sensitive pattern in an MCP tool module.")
        for line, row in enumerate(source.splitlines(), 1)
        for rule, pattern in JS_REVIEW if pattern.search(row)
    ]


def audit_path(path: Path):
    scanners = {".py": audit_python, ".js": audit_js, ".ts": audit_js,
                ".mjs": audit_js, ".cjs": audit_js, ".mts": audit_js, ".cts": audit_js}
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
