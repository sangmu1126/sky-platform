"""Preserve recognized Python authentication boundaries during deployment repair.

These are conservative syntactic invariants, not a semantic code-safety proof.
Application-specific authorization must also be tested outside this allowlist.
"""

import ast
from collections import Counter

_AUTH_CALLS = {
    "authorize",
    "check_permission",
    "verify_token",
    "verify_jwt",
    "require_auth",
    "require_permission",
    "get_current_user",
    "login_required",
    "permission_required",
    "roles_required",
    "requires_auth",
    "requires_roles",
    "Security",
    "Depends",
    "permission_classes",
    "authentication_classes",
    "csrf_protect",
    "ensure_csrf_cookie",
    "require_POST",
    "jwt_required",
    "fresh_jwt_required",
    "admin_required",
}
_EXECUTION_CALLS = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "os.system",
    "os.popen",
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_call",
    "subprocess.check_output",
}


def _name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _name(node.value) + "." + node.attr
    return ""


def _dump(node):
    return ast.dump(node, include_attributes=False)


def _auth_names(tree):
    names = _AUTH_CALLS | {"jwt.decode", "jwt.verify"}
    for item in ast.walk(tree):
        if isinstance(item, ast.ImportFrom):
            for alias in item.names:
                if alias.name in _AUTH_CALLS or item.module == "jwt" and alias.name in {"decode", "verify"}:
                    names.add(alias.asname or alias.name)
        elif isinstance(item, ast.Import):
            for alias in item.names:
                if alias.name == "jwt":
                    names.update({(alias.asname or "jwt") + ".decode", (alias.asname or "jwt") + ".verify"})
    return names


def _auth_call(node, names):
    name = _name(node.func)
    return name in names or name.split(".")[-1] in names


def _auth(node, names):
    return any(isinstance(item, ast.Call) and _auth_call(item, names) for item in ast.walk(node))


def _rejects(node):
    for item in ast.walk(node):
        if isinstance(item, ast.Call) and _name(item.func).split(".")[-1] in {"HTTPException", "abort"}:
            if any(isinstance(arg, ast.Constant) and arg.value in (401, 403) for arg in item.args):
                return True
            if any(
                arg.arg == "status_code"
                and isinstance(arg.value, ast.Constant)
                and arg.value.value in (401, 403)
                for arg in item.keywords
            ):
                return True
        if (
            isinstance(item, ast.Return)
            and isinstance(item.value, ast.Tuple)
            and any(isinstance(arg, ast.Constant) and arg.value in (401, 403) for arg in item.value.elts)
        ):
            return True
    return False


def _invariants(tree):
    values = Counter()
    names = _auth_names(tree)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                name = _name(decorator.func if isinstance(decorator, ast.Call) else decorator).split(".")[-1]
                if name in names or _auth(decorator, names):
                    values[(node.name, "decorator", _dump(decorator))] += 1
            # Do not permit inserting an early return before a recognized guard.
            # Edits after that guard (e.g. adding await to DB calls) remain possible.
            for index, statement in enumerate(node.body):
                if (
                    isinstance(statement, ast.If) and (_auth(statement.test, names) or _rejects(statement))
                ) or _auth(statement, names):
                    prefix = tuple(_dump(item) for item in node.body[: index + 1])
                    values[(node.name, "guard_prefix", prefix)] += 1
                    break
        if isinstance(node, ast.Call) and _auth_call(node, names):
            values[("authorization_call", _dump(node))] += 1
    return values


def check_python_patch(before, after):
    if max(len(before.encode()), len(after.encode())) > 1024 * 1024:
        raise ValueError("Security policy requires bounded Python patches")
    try:
        original, candidate = ast.parse(before), ast.parse(after)
    except SyntaxError:
        raise ValueError("Security policy requires parseable Python patches") from None
    for tree in (original, candidate):
        stack, count = [(tree, 0)], 0
        while stack:
            node, depth = stack.pop()
            count += 1
            if count > 100000 or depth > 128:
                raise ValueError("Security policy requires bounded Python syntax trees")
            stack.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
    if _invariants(original) - _invariants(candidate):
        raise ValueError("Security policy rejects changes to recognized authentication guards")
    roots = set()
    names = _auth_names(original)
    for node in ast.walk(original):
        if isinstance(node, ast.Call) and _auth_call(node, names):
            roots.add(_name(node.func).split(".")[0])
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                name = _name(decorator.func if isinstance(decorator, ast.Call) else decorator)
                if name in names or name.split(".")[-1] in names:
                    roots.add(name.split(".")[0])

    def bindings(tree):
        values = Counter()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)) and any(
                (item.asname or item.name.split(".")[0]) in roots for item in node.names
            ):
                values[_dump(node)] += 1
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name in roots:
                values[_dump(node)] += 1
            if isinstance(
                node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr, ast.Delete)
            ) and any(
                isinstance(item, (ast.Name, ast.Attribute))
                and isinstance(item.ctx, (ast.Store, ast.Del))
                and _name(item).split(".")[0] in roots
                for item in ast.walk(node)
            ):
                values[_dump(node)] += 1
        return values

    # Declarative class policies (e.g. DRF) are guards too, even without a call.
    declarations = {"permission_classes", "authentication_classes", "auth_required", "csrf_protect"}

    def policies(tree):
        result = Counter()

        def visit(node, scope=()):
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                scope = (*scope, node.name)
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(_name(target).split(".")[-1] in declarations for target in targets):
                    result[(scope, _dump(node))] += 1
            for child in ast.iter_child_nodes(node):
                visit(child, scope)

        visit(tree)
        return result

    for node in ast.walk(original):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(_name(target).split(".")[-1] in declarations for target in targets):
                roots.update(item.id for item in ast.walk(node.value) if isinstance(item, ast.Name))

    if policies(original) - policies(candidate):
        raise ValueError("Security policy rejects changing declarative authentication policies")

    if roots and bindings(original) != bindings(candidate):
        raise ValueError("Security policy rejects rebinding recognized authentication helpers")

    def execution(tree):
        aliases = {}
        for item in ast.walk(tree):
            if isinstance(item, ast.Import):
                aliases.update({alias.asname or alias.name: alias.name for alias in item.names})
            elif isinstance(item, ast.ImportFrom) and item.module:
                aliases.update(
                    {alias.asname or alias.name: item.module + "." + alias.name for alias in item.names}
                )

        def resolves(node):
            name = _name(node.func)
            root, *tail = name.split(".")
            return ".".join([aliases.get(root, root), *tail])

        return Counter(
            _dump(node)
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and resolves(node) in _EXECUTION_CALLS
        )

    if execution(candidate) - execution(original):
        raise ValueError("Security policy rejects introducing dynamic execution during deployment repair")
