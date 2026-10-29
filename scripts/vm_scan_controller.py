"""Offline image inspection in a separate disposable role-free VM."""

import os
import tempfile
from pathlib import Path
from uuid import uuid4

from adapters.build.image_security import SCANNER_SHA256, checked_document, publication_security, sha
from adapters.build.vm_builder import IsolatedVmBuilder
from ports.remote_builds import canonical


def scan_in_vm(profile, session, guard, audit, output):
    scanner = Path(os.environ["SKY_OFFLINE_SCANNER_BINARY"])
    database = Path(os.environ["SKY_OFFLINE_SCANNER_DATABASE"])
    expected = os.environ["SKY_OFFLINE_SCANNER_DATABASE_SHA256"]
    for path, limit in ((scanner, 256 * 1024**2), (database, 1024**3)):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
            raise ValueError("Pinned plain bounded scanner materials required")
    if sha(scanner) != SCANNER_SHA256 or sha(database) != expected:
        raise ValueError("Scanner materials differ from operator registration")
    job = str(uuid4())
    controller = IsolatedVmBuilder(profile, session, guard, lambda *_: None, audit=audit)
    with tempfile.TemporaryDirectory(prefix="sky-inspection-controller-") as temporary:
        root = Path(temporary)
        (root / "scan-settings.json").write_bytes(
            canonical({"archive_sha256": sha(output / "image.tar"), "database_sha256": expected})
        )
        with controller.guest(job, root) as (guest, _):
            for source, name in (
                (scanner, "trivy"),
                (database, "scanner-db.tar"),
                (output / "image.tar", "scan-image.tar"),
                (root / "scan-settings.json", "scan-settings.json"),
                (Path(__file__).with_name("isolated_scan_guest.py"), "scan.py"),
                (Path(__file__).resolve().parents[1] / "src/adapters/build/process.py", "process.py"),
            ):
                guest.upload(source, name)
            guest.scan()
            guest.download("scan.json", output / "scan.json", limit=8192)
            guest.download("sbom.json", output / "sbom.json", limit=1024 * 1024)
        # Confirmed scanner teardown occurs before any result can authorize publication.
    materials = checked_document(output / "materials.json", 8192)
    materials["scanner_vm_job"] = job
    (output / "materials.json").write_bytes(canonical(materials))
    security = publication_security(output, sha(output / "image.tar"))
    audit(
        {
            "stage": "image_inspection_passed",
            "job_id": job,
            "sbom_sha256": security["report"]["sbom_sha256"],
            "workload_executed": False,
        }
    )
    return security
