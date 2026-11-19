"""Explicit end-to-end Linux VM smoke with scripted AI tool calls."""
from __future__ import annotations

import argparse
import io
import json
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zipfile
from http.server import ThreadingHTTPServer
from pathlib import Path

from adapters.onprem.vm import RemoteVmComposeAdapter, VmSettings
from application.analysis import AISettings
from interfaces.http.server import App, handler_for
from tests.live.smoke_aws_agent import AwsRepairFixture


class VmInfrastructureFixture:
    """Choose the configured VM while checking both remote adapters were offered."""

    def __init__(self, _settings):
        pass

    def propose(self, files, available_targets, public_access, *, deployment_requirements):
        assert public_access is True, "public access permission was not preserved"
        assert {"aws-ecs-express", "onprem-vm"} <= set(available_targets), available_targets
        assert deployment_requirements["deployment_shape"] == "single-http-container", deployment_requirements
        quote = "http.createServer"
        assert quote in files["server.js"], files.keys()
        return {
            "target": "onprem-vm",
            "workload": "stateless-http",
            "rationale": "설정된 전용 Linux VM의 원격 Docker 경로를 검증합니다.",
            "evidence": [{"file": "server.js", "quote": quote}],
        }


def main():
    parser = argparse.ArgumentParser(
        description="Upload, automatically select, repair, and deploy the sample to a configured VM"
    )
    parser.add_argument("--apply", action="store_true", help="Deploy and then remove a real VM container")
    args = parser.parse_args()

    settings = VmSettings.from_environment()
    reason = RemoteVmComposeAdapter.unavailable_reason(settings)
    if reason:
        raise SystemExit(reason)
    if not args.apply:
        print("읽기 전용 VM 설정 점검 완료. --apply를 지정해야 원격 Docker 리소스를 생성합니다.")
        return

    job_id = None
    job = None
    with tempfile.TemporaryDirectory(prefix="sky-vm-agent-smoke-") as directory:
        root = Path(directory)
        app = App(
            root,
            AISettings("test-fixture", "fixture-model"),
            AwsRepairFixture,
            infrastructure_planner_factory=VmInfrastructureFixture,
            monitor_interval=0,
        )

        class QuietHandler(handler_for(app)):
            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        base = f"http://127.0.0.1:{server.server_port}"

        def request(path, data=None, headers=None):
            request_headers = {"X-Sky-Token": app.token, **(headers or {})}
            request_object = urllib.request.Request(base + path, data=data, headers=request_headers)
            try:
                with opener.open(request_object, timeout=15) as response:
                    return json.load(response)
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", errors="replace")
                raise RuntimeError(f"Sky HTTP {exc.code}: {body}") from exc

        try:
            archive = io.BytesIO()
            fixture = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "apps" / "unready-node"
            with zipfile.ZipFile(archive, "w") as bundle:
                for file in fixture.iterdir():
                    bundle.write(file, file.name)
            job_id = request(
                "/api/deployments",
                archive.getvalue(),
                {
                    "X-Deploy-Target": "auto",
                    "X-Public-Access": "true",
                    "X-Application-Id": "vm-agent-smoke",
                },
            )["id"]
            print("Started automatic VM agent job:", job_id, flush=True)
            for index in range(300):
                job = request("/api/jobs/" + job_id)
                if job["status"] != "running":
                    break
                if index % 15 == 0:
                    stage = job["events"][-1]["stage"] if job["events"] else "-"
                    print("Status:", job["status"], "stage:", stage, flush=True)
                time.sleep(2)
            else:
                raise RuntimeError("VM agent job exceeded the smoke time limit")
            if job["status"] != "succeeded":
                raise AssertionError(json.dumps(job, ensure_ascii=False, indent=2))
            assert job["attempts"] == 1
            assert job["requested_target"] == "auto"
            assert job["target"] == "onprem-vm"
            assert job["vm"] == {
                "ssh_host": settings.ssh_host,
                "ssh_user": settings.ssh_user,
                "public_host": settings.public_host,
            }
            candidates = {item["id"]: item for item in job["infrastructure_plan"]["candidates"]}
            assert candidates["aws-ecs-express"]["status"] == "eligible"
            assert candidates["onprem-vm"]["status"] == "eligible"
            assert candidates["onprem-vm"]["selected"] is True
            assert {change["path"] for change in job["changes"]} == {"package.json", "server.js"}
            health = request("/api/jobs/" + job_id + "/health")
            assert health["healthy"], health
            print("PASS: upload -> requirements -> automatic VM selection -> repair -> public HTTP 200 -> health")
            print("AI mode: SCRIPTED TEST FIXTURE (not live AI)")
            print(json.dumps(job["result"], ensure_ascii=False, indent=2))
        finally:
            server.shutdown()
            server.server_close()
            if job_id:
                adapter = RemoteVmComposeAdapter(
                    lambda stage, message: print(f"[{stage}] {message}", flush=True), root / job_id, settings
                )
                if job and job.get("status") == "succeeded" and job.get("result"):
                    adapter.retire(job["result"], job_id)
                    print("Smoke VM container and image deleted.", flush=True)
                elif job:
                    for number in range(1, job.get("attempts", 0) + 1):
                        adapter.retire_orphan(f"{job_id}-a{number}")
                    print("Smoke failure cleanup completed for recorded attempts.", flush=True)


if __name__ == "__main__":
    main()
