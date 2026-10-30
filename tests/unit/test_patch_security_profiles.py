"""Framework guard/alias bypass regressions for supported repair profiles."""

import pytest

from application.javascript_patch_invariants import check_javascript_patch
from application.patch_invariants import check_python_patch


@pytest.mark.parametrize(
    "before,after",
    [
        (
            "from fastapi import Depends as Inject\ndef route(user=Inject(get_current_user)):\n    return read_db()\n",
            "from fastapi import Depends as Inject\ndef route(user=None):\n    return read_db()\n",
        ),
        (
            'import jwt as tokens\ndef route(raw):\n    tokens.decode(raw, key, algorithms=["RS256"])\n    return read_db()\n',
            "import jwt as tokens\ndef route(raw):\n    return read_db()\n",
        ),
        (
            "from rest_framework.permissions import IsAuthenticated\nclass View:\n    permission_classes=[IsAuthenticated]\n",
            "from rest_framework.permissions import IsAuthenticated\nclass View:\n    permission_classes=[]\n",
        ),
        (
            "from rest_framework.permissions import IsAuthenticated\nclass View:\n    permission_classes=[IsAuthenticated]\n",
            "from rest_framework.permissions import IsAuthenticated\nIsAuthenticated=AllowAny\nclass View:\n    permission_classes=[IsAuthenticated]\n",
        ),
        (
            "from flask_jwt_extended import jwt_required as protected\n@protected()\ndef route():\n    return read_db()\n",
            "from flask_jwt_extended import jwt_required as protected\ndef route():\n    return read_db()\n",
        ),
        (
            "def route():\n    return read_db()\n",
            'from subprocess import run as launch\ndef route():\n    launch(["sh"])\n    return read_db()\n',
        ),
    ],
)
def test_python_guard_removal_alias_rebinding_and_execution_are_rejected(before, after):
    with pytest.raises(ValueError, match="Security policy"):
        check_python_patch(before, after)


def test_aliased_guard_allows_existing_async_database_repair():
    before = "from flask_jwt_extended import jwt_required as protected\n@protected()\ndef route():\n    return read_db()\n"
    after = before.replace("def route", "async def route").replace(
        "return read_db()", "return await read_db()"
    )
    check_python_patch(before, after)


@pytest.mark.parametrize(
    "statement",
    [
        "const {exec: launch}=require('child_process'); launch('sh');",
        "import {runInNewContext as run} from 'node:vm'; run('x');",
        "const m=require(process.env.MODULE);",
        "const m=require('node:child_\\x70rocess');",
    ],
)
def test_javascript_aliases_and_computed_modules_cannot_hide_execution(statement):
    with pytest.raises(ValueError, match="Security policy"):
        check_javascript_patch("app.js", "const x=1;", "const x=1;" + statement)


@pytest.mark.parametrize("guard", ["passport", "AuthGuard", "csrf", "ensureLoggedIn"])
def test_javascript_framework_guards_cannot_be_removed(guard):
    before = f'app.get("/private",{guard}, (req,res)=>res.send(db.read()));'
    after = 'app.get("/private",(req,res)=>res.send(db.read()));'
    with pytest.raises(ValueError, match="Security policy"):
        check_javascript_patch("app.js", before, after)
