"""Build one checked container image for local and cloud adapters."""

from __future__ import annotations

import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path

from application.deployment_core import DeploymentPlan, source_digest

RDS_CA_CONTAINER_PATH = "/app/.sky-rds-ca.pem"


class ImageBuilder:
    """Shared image preparation for local and cloud execution targets."""

    def __init__(self, command, event):
        self.command, self.event = command, event

    @contextmanager
    def prepare(self, project: Path, plan: DeploymentPlan, extra_ca_bundle: Path | None = None):
        if not plan.source_digest or source_digest(project) != plan.source_digest:
            raise ValueError("Source changed after analysis; upload and analyze again")
        from application.source_secrets import reject_embedded_credentials

        reject_embedded_credentials(project)
        if plan.dockerfile_source == "existing" and (project / "Dockerfile").read_text() != plan.dockerfile:
            raise ValueError("Existing Dockerfile changed after analysis")
        with tempfile.TemporaryDirectory(prefix="sky-build-") as temporary:
            context = Path(temporary) / "app"
            shutil.copytree(project, context, symlinks=True)
            if source_digest(context) != plan.source_digest:
                raise ValueError("Source changed while preparing image; upload and analyze again")
            if plan.dockerfile_source != "existing":
                (context / "Dockerfile").write_text(plan.dockerfile)
            if extra_ca_bundle is not None:
                ca_name = ".sky-rds-ca.pem"
                shutil.copyfile(extra_ca_bundle, context / ca_name)
                dockerfile = context / "Dockerfile"
                content = dockerfile.read_text()
                directive = (
                    f"\nCOPY .sky-rds-ca.pem {RDS_CA_CONTAINER_PATH}\n"
                    "COPY .sky-rds-ca.pem /etc/ssl/certs/sky-rds-global-bundle.pem\n"
                    f"ENV NODE_EXTRA_CA_CERTS={RDS_CA_CONTAINER_PATH}\n"
                )
                if plan.runtime in {"python", "python-asgi", "python-wsgi"}:
                    directive += f"ENV PGSSLROOTCERT={RDS_CA_CONTAINER_PATH}\n"
                if directive not in content:
                    dockerfile.write_text(content.rstrip("\n") + directive)
            ignore = context / ".dockerignore"
            current_ignore = ignore.read_text() if ignore.exists() else ""
            ignore.write_text(
                current_ignore.rstrip("\n")
                + "\n.git\nnode_modules\n.venv\nvenv\n__pycache__\n.env\n.env.*\n"
                + ("!.sky-rds-ca.pem\n" if extra_ca_bundle is not None else "")
            )
            yield context

    def build(
        self,
        project: Path,
        plan: DeploymentPlan,
        image: str,
        platform: str | None = None,
        extra_ca_bundle: Path | None = None,
        offline_bases=None,
    ):
        import os

        if (
            os.environ.get("ECS_CONTAINER_METADATA_URI_V4")
            or os.environ.get("ECS_CONTAINER_METADATA_URI")
            or os.environ.get("SKY_REQUIRE_ISOLATED_BUILDS") == "true"
        ):
            raise ValueError(
                "Hosted user code requires a sealed disposable VM; shared Docker builds are disabled"
            )
        with self.prepare(project, plan, extra_ca_bundle) as context:
            self.event("building", "Building application image")
            args = ["docker", "build", "--label", "app=sky"]
            if offline_bases is not None:
                from adapters.build.offline import validate_offline_dockerfile

                validate_offline_dockerfile((context / "Dockerfile").read_text(), offline_bases, self.command)
                args += ["--network", "none", "--pull=false"]
            if platform:
                args += ["--platform", platform]
            self.command(args + ["-t", image, str(context)])
            if platform:
                try:
                    try:
                        actual = (
                            self.command(
                                [
                                    "docker",
                                    "image",
                                    "inspect",
                                    "--platform",
                                    platform,
                                    "--format",
                                    "{{.Os}}/{{.Architecture}}",
                                    image,
                                ]
                            )
                            .strip()
                            .lower()
                        )
                    except Exception as exc:
                        raise ValueError(
                            f"빌드 이미지의 {platform} 플랫폼을 Docker에서 확인할 수 없습니다."
                        ) from exc
                    if actual != platform:
                        raise ValueError(
                            f"빌드 이미지 플랫폼 불일치: {platform}이 필요하지만 {actual or '불명'}입니다."
                        )
                    self.event("building", f"이미지 플랫폼 확인 완료: {actual}")
                except Exception:
                    try:
                        self.command(["docker", "image", "rm", image], timeout=30)
                    except Exception:  # noqa: BLE001 -- preserve build error after best-effort image cleanup
                        self.event("cleanup", "플랫폼 확인 실패 후 로컬 이미지 정리 확인 필요: " + image)
                    raise
        return image
