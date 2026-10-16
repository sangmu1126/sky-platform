"""Real Docker + authenticated HTTP cleanup retry; no AWS, GitHub or AI calls.

Run on the machine hosting the local Docker daemon. Uses two uniquely named
containers and image tags; final cleanup is restricted to this run's labels.
Docker build cache is left intact. The base image may be downloaded.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import threading
import urllib.error
import urllib.request
import uuid
from dataclasses import asdict
from datetime import UTC, datetime
from http.server import ThreadingHTTPServer
from pathlib import Path

from adapters.local.docker import LocalDockerAdapter
from application.analysis import AISettings, redact
from application.deployment_core import make_plan
from interfaces.http.server import App, handler_for

BASE_IMAGE = "python:3.13-alpine"
LABEL = "sky-cleanup-smoke"


def docker(*args, required=True):
    result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=300, check=False)
    if required and result.returncode:
        raise RuntimeError(redact(result.stderr[-800:]))
    return result


def inspect(kind, name):
    result = docker(kind, "inspect", name, required=False)
    if result.returncode == 0:
        return json.loads(result.stdout)[0]
    if any(
        message in result.stderr.lower()
        for message in ("no such image", "no such object", "no such container")
    ):
        return None
    raise RuntimeError("Cannot inspect test resource: " + name)


def run():
    run_id = uuid.uuid4().hex
    ids = [uuid.uuid4().hex[:16], uuid.uuid4().hex[:16]]
    report = {
        "kind": "local-docker-http-cleanup-retry",
        "run_id": run_id,
        "started_at": datetime.now(UTC).isoformat(),
        "checks": {},
        "image_ids": {},
        "status": "running",
    }
    base_existed = inspect("image", BASE_IMAGE) is not None
    server = worker = None
    with tempfile.TemporaryDirectory(prefix="sky-cleanup-retry-") as temporary:
        app = App(Path(temporary) / "state", AISettings("", ""), monitor_interval=0, github_poll_interval=0)
        principal = app.authenticator.authenticate_request({"X-Sky-Token": app.token})
        owner = {"organization_id": principal.organization_id, "created_by": principal.user_id}
        results = {}
        try:
            report["docker_version"] = docker("version", "--format", "{{.Server.Version}}").stdout.strip()
            for index, job_id in enumerate(ids):
                project = app.root / job_id / "source"
                project.mkdir(parents=True)
                (project / "Dockerfile").write_text(
                    f"FROM {BASE_IMAGE}\nLABEL {LABEL}={run_id}\nWORKDIR /app\nCOPY . .\n"
                    'EXPOSE 3000\nCMD ["python", "-m", "http.server", "3000", "--bind", "0.0.0.0"]\n'
                )
                (project / "index.html").write_text("old" if index == 0 else "new")
                (project / "ready").write_text("ready")
                plan = make_plan(project, "dockerfile", None, health_path="/ready")
                result = LocalDockerAdapter(lambda *_: None).deploy(project, plan, job_id, {})
                results[job_id] = result
                report.setdefault("image_ids", {})[job_id] = inspect("image", result["image"])["Id"]
                app.jobs[job_id] = {
                    "id": job_id,
                    "mode": "agent",
                    "application_id": "cleanup-smoke",
                    "target": "local-docker",
                    "status": "succeeded",
                    "deployment_state": "active",
                    "project": str(project),
                    "plan": asdict(plan),
                    "events": [],
                    "attempts": 1,
                    "source_digest": plan.source_digest,
                    "result": result,
                    "github_source": {
                        "repository_url": "https://github.com/sky-smoke/fixture",
                        "branch": "main",
                        "subscription_id": run_id[:16],
                        **owner,
                    },
                    **owner,
                }
            old_id, new_id = ids
            old, new = app.jobs[old_id], app.jobs[new_id]
            new.update(git_replaces_local_job_id=old_id, finalization_state="needs_attention")
            app.save(old_id)
            app.save(new_id)

            class QuietHandler(handler_for(app)):
                def log_message(self, *args):
                    pass

            server = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            endpoint = f"http://127.0.0.1:{server.server_port}/api/jobs/{new_id}/finalization/retry"
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

            def retry(token):
                request = urllib.request.Request(endpoint, data=b"", headers={"X-Sky-Token": token})
                try:
                    with opener.open(request, timeout=90) as response:
                        return response.status, json.load(response)
                except urllib.error.HTTPError as error:
                    with error:
                        return error.code, json.load(error)

            assert retry("invalid-token")[0] == 403
            report["checks"]["unauthenticated_retry_rejected"] = True
            docker("exec", new["result"]["container"], "rm", "/app/ready")
            status, outcome = retry(app.token)
            assert status == 200 and outcome["finalization_state"] == "needs_attention"
            assert inspect("container", old["result"]["container"])["State"]["Running"]
            assert old["deployment_state"] == "active"
            report["checks"]["unhealthy_current_preserves_old"] = True
            docker(
                "exec",
                new["result"]["container"],
                "python",
                "-c",
                "from pathlib import Path; Path('/app/ready').write_text('ready')",
            )
            status, outcome = retry(app.token)
            assert status == 200 and outcome["finalization_state"] == "complete"
            assert inspect("container", old["result"]["container"]) is None
            assert inspect("image", old["result"]["image"]) is None
            assert inspect("container", new["result"]["container"])["State"]["Running"]
            with opener.open(new["result"]["url"], timeout=5) as response:
                assert response.read() == b"new"
            assert new["status"] == "succeeded" and old["deployment_state"] == "deleted"
            report["checks"]["healthy_current_retires_only_old"] = True
            assert retry(app.token)[0] == 400
            report["checks"]["completed_retry_does_not_repeat_delete"] = True
            report["status"] = "passed"
        except (
            AssertionError,
            RuntimeError,
            ValueError,
            OSError,
            KeyError,
            subprocess.SubprocessError,
        ) as error:
            report.update(status="failed", error=redact(str(error))[:1000], error_type=type(error).__name__)
        finally:
            if server is not None:
                server.shutdown()
                server.server_close()
            if worker is not None:
                worker.join(timeout=5)
            cleanup_errors = []
            for job_id in ids:
                container, image = f"sky-{job_id}", f"sky/{job_id}:latest"
                for kind, name, command in [
                    ("container", container, ("rm", "-f", container)),
                    ("image", image, ("image", "rm", image)),
                ]:
                    item = inspect(kind, name)
                    if item is None:
                        continue
                    if (item.get("Config", {}).get("Labels") or {}).get(LABEL) != run_id:
                        cleanup_errors.append("ownership mismatch: " + name)
                    elif docker(*command, required=False).returncode or inspect(kind, name) is not None:
                        cleanup_errors.append("cleanup not confirmed: " + name)
            if (
                not base_existed
                and inspect("image", BASE_IMAGE) is not None
                and docker("image", "rm", BASE_IMAGE, required=False).returncode
            ):
                cleanup_errors.append("base image retained: " + BASE_IMAGE)
            report["cleanup"] = {
                "errors": cleanup_errors,
                "run_resources_removed": not cleanup_errors,
                "docker_build_cache": "retained",
            }
            if cleanup_errors:
                report["status"] = "failed"
    report["finished_at"] = datetime.now(UTC).isoformat()
    return report


if __name__ == "__main__":
    receipt = run()
    print(json.dumps(receipt, ensure_ascii=False, indent=2))
    raise SystemExit(receipt["status"] != "passed")
