"""Opt-in adaptation of the reviewed TUG ZIP; no AI or generic JS rewriting.

The source archive stays intact. Exact reviewed files are required because the
single-writer/round-drain contract depends on every score write and room tick.
Preparation alone neither provisions a database nor authorizes a transfer.
"""

import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path

from adapters.database.sqlite_snapshot import compile_sqlite_snapshot
from application.deployment_core import MAX_UPLOAD, extract_project, source_digest
from assets import ASSET_ROOT

REVIEWED_FILES = {
    ".dockerignore": "b63cda77bb7d2255a43b8df03a5f839cd276f514783dcfe4247bff3a57f7736b",
    "package-lock.json": "bc99b2b559badc945a24319ffd31ea255c5cff862e0d4897122a42faa680e286",
    "server.js": "0001e5410a6e8a581ba8cd211731015aa5acfdb3e07b5e4d5d5f8e04c75f7f84",
    "room.js": "4e2b04e855addaeb4a4f453ac3cbc00af12886a2033fda2018b542d9f4942c2d",
    "db.js": "1d1a8f0ba8412f7c8a0c8b617b9670609c0170cfa221f194245131a945606556",
    "schema.sql": "db986e412d840e329abf266f2f0338b2cf976ba0290bb8b980428ea26334cb95",
    "static.js": "75c2334d0843c0a3c98b57a32f175f78d8bded9dd9836e5dd31adc3f4ce4bf0d",
    "package.json": "2d48d0f007fd925c86e340b270ff9e81b8e74fcdc9768369b0d5119e145f6d71",
    "Dockerfile": "93f1d66b72929fd1da10650a25ab5e0ebd4f55e6199c8cf8a79c2e4b2179f8c1",
}


def _replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError("Reviewed game patch context differs")
    return text.replace(old, new, 1)


def prepare_tug_archive(archive: Path, destination: Path):
    """Build a new work tree, record original identity, and compile bounded SQL.

    Caller must subsequently resolve/pin the pg dependency lock with scripts off,
    build/rehearse, register credentials/TLS/controllers, and obtain execution
    approval. No local settings or Secret is placed in the returned source tree.
    """
    archive, destination = Path(archive), Path(destination)
    if archive.is_symlink() or not archive.is_file() or not 0 < archive.stat().st_size <= MAX_UPLOAD:
        raise ValueError("Bounded regular game ZIP required")
    if destination.exists():
        raise ValueError("New empty game preparation destination required")
    archive_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    destination.mkdir(parents=True)
    project = extract_project(archive, destination)
    for name, expected in REVIEWED_FILES.items():
        file = project / name
        if not file.is_file() or hashlib.sha256(file.read_bytes()).hexdigest() != expected:
            raise ValueError(f"Unreviewed TUG input: {name}")
    # Startup hooks or other executable inputs invalidate this narrow adapter.
    allowed = set(REVIEWED_FILES) | {"package-lock.json", "data/scores.db", "README.txt", "debug.html"}
    if any(
        p.relative_to(project).as_posix() not in allowed
        and not p.relative_to(project).as_posix().startswith("public/")
        for p in project.rglob("*")
        if p.is_file()
    ):
        raise ValueError("Unreviewed additional game file")
    original_revision = source_digest(project)
    snapshot = compile_sqlite_snapshot(project / "data/scores.db")
    if set(snapshot.schema) != {"rounds"}:
        raise ValueError("Reviewed game rounds schema required")
    expected_columns = [
        "id",
        "started_at",
        "ended_at",
        "winner",
        "taps_a",
        "taps_b",
        "players_a",
        "players_b",
    ]
    if [c["name"] for c in snapshot.schema["rounds"]] != expected_columns:
        raise ValueError("Reviewed game rounds columns required")
    if [c["type"] for c in snapshot.schema["rounds"]] != ["INTEGER"] * 3 + ["TEXT"] + ["INTEGER"] * 4:
        raise ValueError("Reviewed game rounds types required")
    if [c["primary_key"] for c in snapshot.schema["rounds"]] != [True] + [False] * 7:
        raise ValueError("Reviewed game primary key required")
    if [c["required"] for c in snapshot.schema["rounds"]] != [False] + [True] * 7:
        raise ValueError("Reviewed game required columns differ")
    with closing(
        sqlite3.connect((project / "data/scores.db").resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
    ) as db:
        for row in db.execute(
            "SELECT id,started_at,ended_at,winner,taps_a,taps_b,players_a,players_b FROM rounds"
        ):
            if (
                any(type(v) is not int or not 0 <= v <= 2**53 - 1 for i, v in enumerate(row) if i != 3)
                or row[0] < 1
                or row[1] > row[2]
                or row[3] not in {"A", "B", "DRAW"}
            ):
                raise ValueError("Game data exceeds its safe numeric and round contract")

    server = (project / "server.js").read_text()
    server = _replace_once(
        server,
        "const { openScores } = require('./db');",
        """const { openScores } = require('./db');
const { createGate, controlServer } = require('./sky-write-gate.cjs');
const { createHash } = require('node:crypto');
function migrationConfig() {
  const name = process.env.SKY_GAME_MIGRATION_CONFIG;
  if (!name) throw new Error('Registered migration configuration required');
  return JSON.parse(fs.readFileSync(name, 'utf8'));
}""",
    )
    server = _replace_once(
        server,
        "  let pendingScores = scoresReady;",
        """  let scoreFailure = false;
  const gate = createGate(options.migration || migrationConfig(), {
    async drain() {
      const deadline = Date.now() + 45000;
      while (['playing', 'countdown'].includes(room.snapshot(clock()).phase)) {
        if (Date.now() >= deadline) throw new Error('Active round did not finish');
        await new Promise(resolve => setTimeout(resolve, 25));
      }
      await pendingScores;
      if (scoreFailure) throw new Error('Uncertain score write requires reconciliation');
      for (const ws of clients.keys()) ws.close(1012, 'environment_transfer');
      const until = Date.now() + 2000;
      while (clients.size && Date.now() < until) await new Promise(resolve => setTimeout(resolve, 10));
      for (const ws of clients.keys()) ws.terminate();
    },
    async probe() { await scoresReady; if (!scores) return false; await scores.summary(); return true; },
  });
  const control = options.noControlListener ? null : controlServer(gate, options.migration || migrationConfig());
  if (control) control.listen((options.migration || migrationConfig()).control_port, '0.0.0.0');
  let pendingScores = scoresReady;""",
    )
    server = _replace_once(
        server,
        "  async function handleRequest(req, res) {",
        "  server.migration = gate;\n\n  async function handleRequest(req, res) {",
    )
    server = _replace_once(
        server,
        "  const server = http.createServer((req, res) => {",
        """  const createServer = options.noControlListener ? http.createServer : handler => require('node:https').createServer({
    key: fs.readFileSync(migrationConfig().tls_key), cert: fs.readFileSync(migrationConfig().tls_cert), minVersion: 'TLSv1.2',
  }, handler);
  const server = createServer((req, res) => {""",
    )
    server = _replace_once(
        server,
        "    pendingScores = task.catch(() => {});",
        "    pendingScores = task.catch(() => { scoreFailure = true; gate.fail(); });",
    )
    server = _replace_once(
        server,
        "storage: 'sqlite', replicas: 1",
        "storage: 'postgresql', replicas: 1, writesBlocked: gate.closed, acceptingPlayers: gate.canJoin, binding_hash: createHash('sha256').update(JSON.stringify((options.migration || migrationConfig()).binding, function(key, value) { return value && !Array.isArray(value) && typeof value === 'object' ? Object.fromEntries(Object.entries(value).sort(([a],[b]) => a < b ? -1 : a > b ? 1 : 0)) : value; })).digest('hex')",
    )
    server = _replace_once(
        server,
        "{ ...summary, recent }",
        "{ ...summary, recent, binding_hash: createHash('sha256').update(JSON.stringify((options.migration || migrationConfig()).binding, function(key, value) { return value && !Array.isArray(value) && typeof value === 'object' ? Object.fromEntries(Object.entries(value).sort(([a],[b]) => a < b ? -1 : a > b ? 1 : 0)) : value; })).digest('hex') }",
    )
    server = _replace_once(
        server,
        "    const url = new URL(req.url, 'http://localhost');\n    if (url.pathname !== '/ws')",
        "    const url = new URL(req.url, 'http://localhost');\n    if (!gate.canJoin) return reject(socket, 503);\n    if (url.pathname !== '/ws')",
    )
    server = _replace_once(
        server,
        "    if (msg.type === 'join' && !client.joined) {",
        "    if (msg.type === 'join' && !gate.canJoin) return ws.close(1012, 'environment_transfer');\n    if (msg.type === 'join' && !client.joined) {",
    )
    server = _replace_once(
        server,
        "    const result = room.tick(now);",
        "    if (!gate.canPlay || gate.draining && !['playing', 'countdown'].includes(room.snapshot(now).phase)) return;\n    const result = room.tick(now);",
    )
    server = _replace_once(server, "      everyone({ type: 'result', ...result });\n", "")
    server = _replace_once(
        server,
        "        await scores.saveRound(result);",
        "        await scores.saveRound(result);\n        everyone({ type: 'result', ...result });",
    )
    server = _replace_once(
        server,
        "      stopTimers();\n      for (const ws of clients.keys()) ws.terminate();",
        "      stopTimers();\n      if (control) control.close();\n      for (const ws of clients.keys()) ws.terminate();",
    )
    server = server.replace(
        "(SQLite scores, single instance)", "(PostgreSQL scores, registered single writer)"
    )
    (project / "server.js").write_text(server)
    (project / "db.js").write_bytes((ASSET_ROOT / "runtime/tug-postgres.cjs").read_bytes())
    (project / "sky-write-gate.cjs").write_bytes((ASSET_ROOT / "runtime/tug-write-gate.cjs").read_bytes())
    (project / "sky-bootstrap.cjs").write_bytes((ASSET_ROOT / "runtime/tug-bootstrap.cjs").read_bytes())
    (project / "sky-initial-data.sql").write_text(snapshot.sql)
    (project / ".dockerignore").write_text(
        (project / ".dockerignore").read_text() + "\ndata/\nsky-initial-data.sql\n"
    )
    docker = (project / "Dockerfile").read_text()
    docker = docker.replace("PORT=8080", "PORT=8443").replace("EXPOSE 8080", "EXPOSE 8443 8444")
    docker = docker.replace('CMD ["npm", "start"]', 'CMD ["node", "sky-bootstrap.cjs"]')
    health = "const fs=require('fs'),c=JSON.parse(fs.readFileSync(process.env.SKY_GAME_MIGRATION_CONFIG));require('https').get({host:'127.0.0.1',port:process.env.PORT||8443,servername:c.tls_name,path:'/health',ca:fs.readFileSync(c.ca_file)},r=>{r.resume();process.exit(r.statusCode===200?0:1)}).on('error',()=>process.exit(1))"
    docker = (
        "\n".join(
            "HEALTHCHECK --interval=30s --timeout=5s CMD node -e " + json.dumps(health)
            if line.startswith("HEALTHCHECK ")
            else line
            for line in docker.splitlines()
        )
        + "\n"
    )
    (project / "Dockerfile").write_text(docker)
    package = json.loads((project / "package.json").read_text())
    package["dependencies"]["pg"] = "8.16.3"
    (project / "package.json").write_text(json.dumps(package, indent=2) + "\n")
    return {
        "profile": "reviewed_tug_round_drain_v1",
        "project": str(project),
        "archive_sha256": archive_digest,
        "original_revision": original_revision,
        "prepared_revision": source_digest(project),
        "sqlite_sha256": snapshot.source_sha256,
        "row_counts": snapshot.row_counts,
        "lock_update_required": True,
        "starts_write_closed": True,
        "websocket_reconnect_required": True,
        "zero_downtime": False,
        "deployed": False,
    }
