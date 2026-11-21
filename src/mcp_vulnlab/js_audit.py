"""Syntax-based JavaScript and TypeScript MCP source review."""

import re

from tree_sitter import Language, Parser
import tree_sitter_javascript
import tree_sitter_typescript

from .metadata_unicode import HIDDEN, canonical
from .static_audit import Advisory, INSTRUCTION

LANGUAGES = {
    "js": Language(tree_sitter_javascript.language()),
    "ts": Language(tree_sitter_typescript.language_typescript()),
    "tsx": Language(tree_sitter_typescript.language_tsx()),
}
DECLARATIONS = {"registerTool", "tool", "setRequestHandler"}
FILE_METHODS = {
    "readFile", "writeFile", "appendFile", "createReadStream", "createWriteStream",
    "open", "unlink", "rm", "rmdir", "mkdir", "readdir", "stat", "lstat", "access",
    "copyFile", "rename", "cp", "truncate", "chmod",
}
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "request"}
JS_ESCAPE = re.compile(r"\\(?:u\{([0-9a-fA-F]{1,6})\}|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|(\\))")


def walk(root):
    pending = [root]
    while pending:
        node = pending.pop()
        yield node
        pending.extend(reversed(node.named_children))


def source(node):
    return node.text.decode("utf-8") if node is not None else ""


def decode_escapes(value):
    def substitute(match):
        if match[4]:
            return "\\"
        point = int(next(group for group in match.groups()[:3] if group), 16)
        return chr(point) if point <= 0x10FFFF else match[0]

    return JS_ESCAPE.sub(substitute, value)


def dynamic(node):
    if node.type == "template_string":
        return any(child.type == "template_substitution" for child in node.named_children)
    if node.type in {"array", "binary_expression", "parenthesized_expression"}:
        return any(dynamic(child) for child in node.named_children if child.type != "comment")
    return node.type not in {"string", "number", "true", "false", "null", "object", "regex"}


def option(node, name):
    for child in node.named_children:
        if child.type == "pair" and source(child.child_by_field_name("key")).strip("'\"") == name:
            return child.child_by_field_name("value")
    return None


def audit_js(text, path):
    extension = path.rsplit(".", 1)[-1]
    language = LANGUAGES["ts" if extension in {"ts", "mts", "cts"} else
                         "tsx" if extension == "tsx" else "js"]
    nodes = list(walk(Parser(language).parse(text.encode("utf-8")).root_node))
    calls = [node for node in nodes if node.type == "call_expression"]
    if not any(source(call.child_by_field_name("function")).rsplit(".", 1)[-1]
               in DECLARATIONS for call in calls):
        return []

    aliases = {}
    for node in nodes:
        if node.type != "import_statement":
            continue
        module = source(node.child_by_field_name("source")).strip("'\"").removeprefix("node:")
        clause = next((child for child in node.named_children if child.type == "import_clause"), None)
        if clause is None or module not in {"child_process", "fs", "fs/promises", "axios"}:
            continue
        module = module.replace("/", ".")
        for child in walk(clause):
            if child.type == "import_specifier":
                name = source(child.child_by_field_name("name"))
                local = source(child.child_by_field_name("alias")) or name
                aliases[local] = f"{module}.{name}"
            elif child.type == "namespace_import":
                aliases[source(child.named_children[-1])] = module
            elif child.type == "identifier" and child.parent == clause:
                aliases[source(child)] = module

    for node in nodes:
        if node.type != "variable_declarator":
            continue
        value = node.child_by_field_name("value")
        if value is None or value.type != "call_expression":
            continue
        if source(value.child_by_field_name("function")) != "require":
            continue
        module = source(value.child_by_field_name("arguments"))[1:-1].strip().strip("'\"")
        module = module.removeprefix("node:").replace("/", ".")
        if module not in {"child_process", "fs", "fs.promises", "axios"}:
            continue
        target = node.child_by_field_name("name")
        if target.type == "identifier":
            aliases[source(target)] = module
        elif target.type == "object_pattern":
            for field in target.named_children:
                if field.type == "shorthand_property_identifier_pattern":
                    aliases[source(field)] = f"{module}.{source(field)}"
                elif field.type == "pair_pattern":
                    key = source(field.child_by_field_name("key"))
                    local = source(field.child_by_field_name("value"))
                    aliases[local] = f"{module}.{key}"

    # Follow immutable query initializers in enclosing lexical blocks.
    constants = {}
    for node in nodes:
        if node.type != "variable_declarator" or node.parent.type != "lexical_declaration":
            continue
        if source(node.parent.children[0]) != "const":
            continue
        name = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
        if name.type == "identifier" and value is not None:
            constants[node.parent.parent, source(name)] = value

    def query_expression(node):
        while node is not None and node.type == "identifier":
            parent = node.parent
            while parent is not None and (parent, source(node)) not in constants:
                parent = parent.parent
            value = constants.get((parent, source(node)))
            if value is None or value.end_byte > node.start_byte:
                break
            node = value
        return node

    findings = set()

    def add(node, rule, message):
        findings.add(Advisory(path, node.start_point.row + 1, rule, message))

    for call in calls:
        function = re.sub(r"\s+", "", source(call.child_by_field_name("function")))
        root, dot, rest = function.partition(".")
        function = aliases.get(root, root) + dot + rest
        receiver, _, method = function.rpartition(".")
        args = call.child_by_field_name("arguments")
        arguments = [arg for arg in args.named_children if arg.type != "comment"] if args else []
        if not arguments:
            continue
        first = arguments[0]
        rule = None
        if method in {"exec", "execSync"} and receiver in {"", "child_process"}:
            rule = "command"
        elif method in {"spawn", "spawnSync"} and receiver in {"", "child_process"}:
            if any(source(option(arg, "shell")) == "true" for arg in arguments[1:]
                   if arg.type == "object") and any(
                dynamic(arg) for arg in arguments[:2] if arg.type != "object"
            ):
                add(call, "command", "Review dynamic command arguments passed to a shell.")
        elif method in FILE_METHODS and receiver in {"", "fs", "fs.promises", "promises"}:
            destinations = arguments[:2] if method in {"copyFile", "rename", "cp"} else [first]
            if any(dynamic(arg) for arg in destinations):
                add(call, "filesystem", "Review dynamic filesystem paths.")
        elif function in {"fetch", "axios"} or (receiver == "axios" and method in HTTP_METHODS):
            destinations = [first] if first.type != "object" else []
            if function != "fetch":
                destinations.extend(option(arg, key) for arg in arguments if arg.type == "object"
                                    for key in ("url", "baseURL"))
            if any(arg is not None and dynamic(arg) for arg in destinations):
                add(call, "network", f"Review dynamic input reaching {function}.")
        elif method in {"query", "execute", "executescript", "prepare"}:
            if first.type == "object":
                first = option(first, "text") or option(first, "sql")
            first = query_expression(first)
            if first is not None and first.type in {"template_string", "binary_expression"}:
                rule = "sql"
        if rule and first is not None and dynamic(first):
            add(call, rule, f"Review dynamic input reaching {function}.")

    metadata_fields = {
        "name", "title", "description", "inputSchema", "outputSchema", "annotations", "_meta",
    }
    for node in nodes:
        if node.type == "pair" and source(node.child_by_field_name("key")).strip("'\"") in metadata_fields:
            fields = [node.child_by_field_name("value")]
        elif node.type == "call_expression" and source(
            node.child_by_field_name("function")
        ).rsplit(".", 1)[-1] in DECLARATIONS:
            args = node.child_by_field_name("arguments")
            fields = [child for child in args.named_children
                      if child.type in {"string", "template_string"}] if args else []
        else:
            continue
        for field in fields:
            if field is None:
                continue
            for literal in walk(field):
                if literal.type not in {"string", "template_string", "property_identifier"}:
                    continue
                value = decode_escapes(source(literal))
                if HIDDEN.search(value):
                    add(literal, "hidden-unicode", "Review hidden Unicode controls in tool metadata.")
                if INSTRUCTION.search(canonical(value)):
                    add(literal, "schema-shadowing", "Review instructional markup in tool metadata.")
    return sorted(findings)
