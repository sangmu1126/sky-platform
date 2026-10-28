"""Preserve recognized Python authentication boundaries during deployment repair.

These are conservative syntactic invariants, not a semantic code-safety proof.
Application-specific authorization must also be tested outside this allowlist.
"""

import ast
from collections import Counter

_AUTH_CALLS = {"authorize", "check_permission", "verify_token", "verify_jwt", "require_auth",
               "require_permission", "get_current_user", "login_required", "permission_required",
               "roles_required", "requires_auth", "requires_roles", "Security", "Depends"}
_EXECUTION_CALLS = {"eval", "exec", "compile", "__import__", "os.system", "os.popen",
                    "subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_call",
                    "subprocess.check_output"}


def _name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _name(node.value) + "." + node.attr
    return ""


def _dump(node):
    return ast.dump(node, include_attributes=False)


def _auth(node):
    return any(isinstance(item, ast.Call) and (_name(item.func).split(".")[-1] in _AUTH_CALLS
               or _name(item.func) in {"jwt.decode", "jwt.verify"}) for item in ast.walk(node))


def _rejects(node):
    for item in ast.walk(node):
        if isinstance(item, ast.Call) and _name(item.func).split(".")[-1] in {"HTTPException", "abort"}:
            if any(isinstance(arg, ast.Constant) and arg.value in (401, 403) for arg in item.args):
                return True
            if any(arg.arg == "status_code" and isinstance(arg.value, ast.Constant)
                   and arg.value.value in (401, 403) for arg in item.keywords):
                return True
        if (isinstance(item, ast.Return) and isinstance(item.value, ast.Tuple)
                and any(isinstance(arg, ast.Constant) and arg.value in (401, 403) for arg in item.value.elts)):
            return True
    return False


def _invariants(tree):
    values = Counter()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                name = _name(decorator.func if isinstance(decorator, ast.Call) else decorator).split(".")[-1]
                if name in _AUTH_CALLS or _auth(decorator):
                    values[(node.name, "decorator", _dump(decorator))] += 1
            # Do not permit inserting an early return before a recognized guard.
            # Edits after that guard (e.g. adding await to DB calls) remain possible.
            for index, statement in enumerate(node.body):
                if (isinstance(statement, ast.If) and (_auth(statement.test) or _rejects(statement))) or _auth(statement):
                    prefix = tuple(_dump(item) for item in node.body[:index + 1])
                    values[(node.name, "guard_prefix", prefix)] += 1
                    break
        if (isinstance(node, ast.Call)
                and (_name(node.func).split(".")[-1] in _AUTH_CALLS or _name(node.func) in {"jwt.decode", "jwt.verify"})):
            values[("authorization_call", _dump(node))] += 1
    return values


def check_python_patch(before, after):
    try:
        original, candidate = ast.parse(before), ast.parse(after)
    except SyntaxError:
        raise ValueError("Security policy requires parseable Python patches") from None
    if _invariants(original) - _invariants(candidate):
        raise ValueError("Security policy rejects changes to recognized authentication guards")
    def execution(tree):
        return Counter(_dump(node) for node in ast.walk(tree)
                       if isinstance(node, ast.Call) and _name(node.func) in _EXECUTION_CALLS)
    if execution(candidate) - execution(original):
        raise ValueError("Security policy rejects introducing dynamic execution during deployment repair")
