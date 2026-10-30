"""Bounded JS/TS AST repair profile: async DB changes, never arbitrary auth edits.

Full syntax identity is retained for protected files, except adding async handlers
and await to existing non-auth calls. Existing awaits/async flags cannot disappear.
Unsupported changes require manual review; no semantic equivalence is claimed.
"""

from collections import Counter
from pathlib import PurePosixPath

_AUTH = {
    "requireauth",
    "require_auth",
    "verifytoken",
    "verify_token",
    "verifyjwt",
    "verify_jwt",
    "checkpermission",
    "is authenticated",
    "isauthenticated",
    "authorize",
    "authenticate",
    "loginrequired",
    "login_required",
    "requiresroles",
    "requirepermission",
    "require_permission",
    "jwt",
}
_FUNCTIONS = {
    "arrow_function",
    "function_expression",
    "function_declaration",
    "generator_function",
    "generator_function_declaration",
    "method_definition",
}
_DYNAMIC = {"eval", "Function", "exec", "execSync", "spawn", "spawnSync"}


def _parse(path, text):
    from tree_sitter import Language, Parser
    import tree_sitter_javascript as js
    import tree_sitter_typescript as ts

    raw = text.encode()
    if len(raw) > 1024 * 1024:
        raise ValueError("Security policy requires bounded JavaScript patches")
    suffix = PurePosixPath(path).suffix
    language = (
        ts.language_tsx()
        if suffix == ".tsx"
        else ts.language_typescript()
        if suffix == ".ts"
        else js.language()
    )
    root = Parser(Language(language)).parse(raw).root_node
    if root.has_error:
        raise ValueError("Security policy requires parseable JavaScript/TypeScript patches")
    return root


def _nodes(root):
    stack = [(root, 0)]
    count = 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > 100000 or depth > 128:
            raise ValueError("Security policy requires bounded syntax trees")
        yield node
        stack.extend((child, depth + 1) for child in reversed(node.named_children))


def _auth(node):
    return any(
        n.type in {"identifier", "property_identifier"}
        and n.text.decode().casefold() in _AUTH
        or n.type == "number"
        and n.text in {b"401", b"403"}
        for n in _nodes(node)
    )


def _canonical(node):
    if node.type == "await_expression" and not _auth(node):
        child = node.named_children[0]
        if child.type == "call_expression":
            return _canonical(child)
    children = tuple(
        _canonical(c)
        for c in node.children
        if c.type != "comment"
        and not (c.type == "async" and node.type in _FUNCTIONS and not _auth_name(node))
    )
    return (node.type, children if node.children else node.text)


def _auth_name(node):
    name = node.child_by_field_name("name")
    return name is not None and name.text.decode().casefold() in _AUTH


def _awaits(root):
    return Counter(_canonical(n.named_children[0]) for n in _nodes(root) if n.type == "await_expression")


def _async(root):
    return Counter(
        _canonical(n)
        for n in _nodes(root)
        if n.type in _FUNCTIONS and any(c.type == "async" for c in n.children)
    )


def check_javascript_patch(path, before, after):
    old, new = _parse(path, before), _parse(path, after)
    # Force the bounded walk before any recursive fingerprint construction.
    list(_nodes(old))
    list(_nodes(new))

    def execution(root):
        return Counter(
            _canonical(n)
            for n in _nodes(root)
            if n.type in {"call_expression", "new_expression"}
            and (n.child_by_field_name("function") or n.child_by_field_name("constructor")) is not None
            and (n.child_by_field_name("function") or n.child_by_field_name("constructor"))
            .text.decode()
            .split(".")[-1]
            in _DYNAMIC
        )

    if execution(new) - execution(old):
        raise ValueError("Security policy rejects introducing JavaScript dynamic execution")
    if _auth(old) and (
        _canonical(old) != _canonical(new) or _awaits(old) - _awaits(new) or _async(old) - _async(new)
    ):
        raise ValueError(
            "Security policy requires manual review beyond existing-call async JavaScript repair"
        )
