"""Bounded Python/Node source evidence for registered workload inventory.

Uploaded code is parsed, never imported or executed. This first profile requires
every runtime source file to be assigned to a registered component and rejects
dynamic imports, custom Dockerfiles, mixed/unsupported languages and unknown
runtime packages. Rejection produces no positive dependency observation.
"""

import ast
import hashlib
import io
import json
import re
import sys
import tokenize
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path, PurePosixPath

from application.deployment_core import ANALYSIS_SUFFIXES, ignored_source_path, source_digest
from domain.environment_transition import _ref
from domain.workload_inventory import RegisteredWorkloadInventory, WorkloadInventorySnapshot
from ports.workload_inventory import WorkloadInventoryUnavailable

_PYTHON_SUFFIXES = {".py"}
_NODE_SUFFIXES = {".cjs", ".js", ".jsx", ".mjs", ".ts", ".tsx"}
_PYTHON_MODULES = {
    "aiohttp": "external_api",
    "asyncpg": "database",
    "celery": "queue",
    "httpx": "external_api",
    "kafka": "queue",
    "pika": "queue",
    "psycopg": "database",
    "psycopg2": "database",
    "redis": "cache",
    "requests": "external_api",
    "socketio": "session_state",
    "sqlalchemy": "database",
    "sqlite3": "database",
    "urllib3": "external_api",
    "websockets": "session_state",
}
_PYTHON_NEUTRAL = {
    "cryptography",
    "django",
    "fastapi",
    "flask",
    "gunicorn",
    "jinja2",
    "jwt",
    "pydantic",
    "pyjwt",
    "starlette",
    "uvicorn",
}
_PYTHON_PACKAGE_IMPORTS = {
    "psycopg-binary": "psycopg",
    "python-socketio": "socketio",
}
_NODE_MODULES = {
    "@aws-sdk/client-s3": "object_store",
    "@aws-sdk/client-sqs": "queue",
    "amqplib": "queue",
    "axios": "external_api",
    "bullmq": "queue",
    "fs": "filesystem",
    "ioredis": "cache",
    "kafkajs": "queue",
    "knex": "database",
    "mysql": "database",
    "mysql2": "database",
    "node-fetch": "external_api",
    "node:fs": "filesystem",
    "pg": "database",
    "postgres": "database",
    "redis": "cache",
    "sequelize": "database",
    "socket.io": "session_state",
    "undici": "external_api",
    "ws": "session_state",
}
_NODE_NEUTRAL = {
    "@fastify/cors",
    "cors",
    "dotenv",
    "express",
    "fastify",
    "helmet",
    "jose",
    "jsonwebtoken",
    "koa",
    "pino",
    "zod",
}
_NODE_BUILTINS = {
    "assert",
    "buffer",
    "crypto",
    "events",
    "os",
    "path",
    "querystring",
    "stream",
    "string_decoder",
    "timers",
    "tls",
    "url",
    "util",
    "worker_threads",
    "zlib",
}


def _source_path(value):
    if not isinstance(value, str):
        raise TypeError("Registered source path required")
    path = PurePosixPath(value)
    if (
        not value
        or len(value.encode()) > 1024
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in value
        or path.as_posix() != value
        or ignored_source_path(path)
    ):
        raise ValueError("Safe registered source path required")
    return path


@dataclass(frozen=True)
class RegisteredStaticSourceInventory:
    inventory: RegisteredWorkloadInventory
    language: str
    component_sources: tuple[tuple[str, tuple[str, ...]], ...]

    def __post_init__(self):
        if not isinstance(self.inventory, RegisteredWorkloadInventory):
            raise TypeError("Registered workload inventory required")
        if self.language not in {"node", "python"}:
            raise ValueError("Bounded Python or Node source profile required")
        if (
            not isinstance(self.component_sources, tuple)
            or tuple(sorted(self.component_sources)) != self.component_sources
            or len({value[0] for value in self.component_sources}) != len(self.component_sources)
        ):
            raise ValueError("Canonical component source registration required")
        expected = tuple(value[0] for value in self.inventory.component_roles)
        if tuple(value[0] for value in self.component_sources) != expected:
            raise ValueError("Every workload component needs a source registration")
        suffixes = _PYTHON_SUFFIXES if self.language == "python" else _NODE_SUFFIXES
        registered_paths = []
        for component_ref, paths in self.component_sources:
            _ref(component_ref)
            if (
                not isinstance(paths, tuple)
                or not paths
                or tuple(sorted(paths)) != paths
                or len(set(paths)) != len(paths)
                or len(paths) > 128
            ):
                raise ValueError("Canonical component runtime sources required")
            for path in paths:
                if _source_path(path).suffix not in suffixes:
                    raise ValueError("Component source differs from registered language")
                registered_paths.append(path)
        if len(registered_paths) > 128 or len(set(registered_paths)) != len(registered_paths):
            raise ValueError("Each bounded runtime source needs exactly one component")

    def document(self):
        value = {
            "schema_version": 1,
            "profile": "registered_static_workload_source_v1",
            "inventory_id": self.inventory.document()["inventory_id"],
            "source_revision": self.inventory.scope.source_revision,
            "language": self.language,
            "component_sources": [[component, list(paths)] for component, paths in self.component_sources],
        }
        digest = hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
        return {**value, "source_registration_id": "WSR-" + digest}


def _read(path, budget):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Registered runtime source must be a plain file")
    size = path.stat().st_size
    if size > 1024 * 1024 or size > budget:
        raise ValueError("Runtime source exceeds static analysis limits")
    data = path.read_bytes()
    if len(data) != size:
        raise ValueError("Runtime source changed during analysis")
    return data


def _python_categories(path, data):
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
        root = ast.parse(data.decode(encoding), filename=path)
    except (SyntaxError, UnicodeDecodeError, ValueError):
        raise ValueError("Python runtime source is not statically parseable") from None
    categories, blockers = set(), set()
    imports = set()
    for node in ast.walk(root):
        if isinstance(node, ast.Import):
            imports.update(value.name.split(".")[0].casefold() for value in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                imports.add(node.module.split(".")[0].casefold())
        elif isinstance(node, ast.Call):
            name = (
                node.func.id
                if isinstance(node.func, ast.Name)
                else node.func.attr
                if isinstance(node.func, ast.Attribute)
                else None
            )
            if name in {"__import__", "eval", "exec", "compile", "import_module"}:
                blockers.add("dynamic_python_execution:" + path)
            if name in {"open", "Path", "read_bytes", "read_text", "write_bytes", "write_text"}:
                categories.add("filesystem")
            if name == "client" and node.args and isinstance(node.args[0], ast.Constant):
                if node.args[0].value == "s3":
                    categories.add("object_store")
                elif node.args[0].value == "sqs":
                    categories.add("queue")
                else:
                    blockers.add("unclassified_provider_client:" + path)
            elif name == "client" and "boto3" in imports:
                blockers.add("dynamic_provider_client:" + path)
    categories.update(_PYTHON_MODULES[module] for module in imports if module in _PYTHON_MODULES)
    if "subprocess" in imports or "importlib" in imports:
        blockers.add("dynamic_python_module_loading:" + path)
    return categories, blockers, imports


def _javascript_categories(path, data):
    import tree_sitter_javascript as javascript
    import tree_sitter_typescript as typescript
    from tree_sitter import Language, Parser

    suffix = PurePosixPath(path).suffix
    language = (
        typescript.language_tsx()
        if suffix == ".tsx"
        else typescript.language_typescript()
        if suffix == ".ts"
        else javascript.language()
    )
    root = Parser(Language(language)).parse(data).root_node
    if root.has_error:
        raise ValueError("Node runtime source is not statically parseable")
    categories, blockers, modules = set(), set(), set()
    stack, count = [(root, 0)], 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > 100000 or depth > 128:
            raise ValueError("Node runtime syntax tree exceeds analysis limits")
        stack.extend((child, depth + 1) for child in reversed(node.named_children))
        argument = None
        if node.type == "import_statement":
            argument = node.child_by_field_name("source")
        elif node.type == "call_expression":
            function = node.child_by_field_name("function")
            if function is not None and function.text in {b"require", b"import"}:
                arguments = node.child_by_field_name("arguments")
                if arguments and len(arguments.named_children) == 1:
                    argument = arguments.named_children[0]
                if argument is None or argument.type != "string":
                    blockers.add("dynamic_node_import:" + path)
                    continue
            elif function is not None and function.text in {b"eval", b"Function"}:
                blockers.add("dynamic_node_execution:" + path)
            elif function is not None and function.text == b"fetch":
                categories.add("external_api")
        if argument is not None and argument.type == "string":
            raw = argument.text.decode(errors="replace")
            module = raw[1:-1]
            if module and not module.startswith((".", "/")):
                modules.add(module.casefold())
    categories.update(_NODE_MODULES[module] for module in modules if module in _NODE_MODULES)
    if modules & {"child_process", "node:child_process", "vm", "node:vm"}:
        blockers.add("dynamic_node_module_loading:" + path)
    return categories, blockers, modules


def _node_package(module):
    parts = module.split("/")
    return "/".join(parts[:2]) if module.startswith("@") else parts[0]


def _declared_import_blockers(language, imported, packages, local_modules):
    if language == "python":
        declared = {_PYTHON_PACKAGE_IMPORTS.get(package, package.replace("-", "_")) for package in packages}
        external = set(_PYTHON_MODULES) | _PYTHON_NEUTRAL | {"boto3"}
        unknown = imported - set(sys.stdlib_module_names) - local_modules - external
        undeclared = (imported & external) - declared - set(sys.stdlib_module_names)
    else:
        package_imports = {_node_package(module) for module in imported}
        builtins = _NODE_BUILTINS | {"child_process", "fs", "vm"}
        builtins |= {"node:" + value for value in builtins}
        external = set(_NODE_MODULES) | _NODE_NEUTRAL
        unknown = package_imports - packages - builtins - external
        undeclared = (package_imports & external) - packages - builtins
    return {
        *("unclassified_runtime_import:" + value for value in unknown),
        *("undeclared_runtime_import:" + value for value in undeclared),
    }


def _requirements(project, language):
    packages, blockers = set(), set()
    if language == "node":
        package = project / "package.json"
        if not package.is_file() or package.is_symlink():
            return packages, {"missing_package_json"}
        try:
            document = json.loads(_read(package, 1024 * 1024))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return packages, {"invalid_package_json"}
        dependencies = document.get("dependencies", {}) if isinstance(document, dict) else None
        if not isinstance(dependencies, dict) or len(dependencies) > 256:
            return packages, {"invalid_runtime_dependencies"}
        for name, version in dependencies.items():
            if (
                not isinstance(name, str)
                or not isinstance(version, str)
                or not re.fullmatch(r"(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+", name)
                or not version.strip()
            ):
                blockers.add("invalid_runtime_package")
            else:
                packages.add(name.casefold())
        unknown = packages - set(_NODE_MODULES) - _NODE_NEUTRAL
        blockers.update("unclassified_runtime_package:" + value for value in unknown)
        return packages, blockers

    requirement_files = [project / "requirements.txt"]
    pyproject = project / "pyproject.toml"
    lines = []
    if requirement_files[0].is_file():
        try:
            lines.extend(_read(requirement_files[0], 1024 * 1024).decode().splitlines())
        except UnicodeDecodeError:
            blockers.add("invalid_requirements")
    if pyproject.is_file():
        import tomllib

        try:
            document = tomllib.loads(_read(pyproject, 1024 * 1024).decode())
            lines.extend(document.get("project", {}).get("dependencies", []))
        except (AttributeError, TypeError, UnicodeDecodeError, tomllib.TOMLDecodeError):
            blockers.add("invalid_pyproject")
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"([A-Za-z0-9][A-Za-z0-9_.-]*)", line)
        if not match or line.startswith(("-", "git+", "http:", "https:")):
            blockers.add("unbounded_python_requirement")
            continue
        packages.add(match.group(1).replace("_", "-").casefold())
    normalized_modules = {value.replace("-", "_") for value in _PYTHON_MODULES}
    neutral = {value.replace("_", "-") for value in _PYTHON_NEUTRAL}
    classified = {value.replace("_", "-") for value in normalized_modules}
    classified.update({"psycopg-binary", "sqlalchemy", "python-socketio"})
    unknown = packages - classified - neutral - {"boto3"}
    blockers.update("unclassified_runtime_package:" + value for value in unknown)
    return packages, blockers


class StaticSourceWorkloadInventoryReader:
    def __init__(self, registration, project, runtime_reader, publisher, *, clock):
        if not isinstance(registration, RegisteredStaticSourceInventory):
            raise TypeError("Registered static source inventory required")
        if not all(
            callable(value)
            for value in (
                getattr(runtime_reader, "collect", None),
                getattr(publisher, "publish", None),
                clock,
            )
        ):
            raise TypeError("Runtime reader, source publisher and clock required")
        self.registration = registration
        self.project = Path(project)
        self.runtime_reader = runtime_reader
        self.publisher = publisher
        self.clock = clock

    def collect(self, inventory, endpoint):
        if inventory != self.registration.inventory or endpoint not in {"source", "target"}:
            raise ValueError("Static source inventory registration changed")
        try:
            report = self._inspect()
            evidence_ref = self.publisher.publish(json.loads(json.dumps(report)))
            if evidence_ref != report["report_id"] or report["status"] != "verified":
                raise ValueError("Static source inventory was not durably verified")
            runtime = self.runtime_reader.collect(inventory, endpoint)
            if not isinstance(runtime, WorkloadInventorySnapshot):
                raise TypeError("Typed runtime workload inventory required")
            return replace(
                runtime,
                evidence_refs=tuple(sorted({*runtime.evidence_refs, evidence_ref})),
            )
        except Exception:  # noqa: BLE001 -- source/runtime diagnostics stay out of gate responses
            raise WorkloadInventoryUnavailable("Registered static workload inventory unavailable") from None

    def _inspect(self):
        registration = self.registration
        project = self.project
        if not project.is_dir() or project.is_symlink() or (project / "Dockerfile").exists():
            raise ValueError("Plain generated-runtime source directory required")
        before = source_digest(project)
        if before != registration.inventory.scope.source_revision:
            raise ValueError("Source revision differs from workload registration")
        supported = _PYTHON_SUFFIXES if registration.language == "python" else _NODE_SUFFIXES
        code_files, unsupported = [], []
        for path in sorted(project.rglob("*")):
            relative = PurePosixPath(path.relative_to(project).as_posix())
            if ignored_source_path(relative) or not path.is_file():
                continue
            if path.suffix in supported:
                code_files.append(relative.as_posix())
            elif path.suffix in ANALYSIS_SUFFIXES:
                unsupported.append(relative.as_posix())
        assigned = {path for _, paths in registration.component_sources for path in paths}
        blockers = []
        if len(code_files) > 128 or set(code_files) != assigned:
            blockers.append("runtime_source_assignment_incomplete")
        if unsupported:
            blockers.append("unsupported_runtime_language")
        packages, package_blockers = _requirements(project, registration.language)
        blockers.extend(package_blockers)
        local_modules = {
            PurePosixPath(path).parts[0].removesuffix(PurePosixPath(path).suffix) for path in code_files
        }
        by_component = {}
        imported = set()
        files, budget = [], 4 * 1024 * 1024
        for component_ref, paths in registration.component_sources:
            categories = set()
            for relative in paths:
                data = _read(project / relative, budget)
                budget -= len(data)
                found, found_blockers, found_imports = (
                    _python_categories(relative, data)
                    if registration.language == "python"
                    else _javascript_categories(relative, data)
                )
                categories.update(found)
                imported.update(found_imports)
                blockers.extend(found_blockers)
                files.append(
                    {
                        "path": relative,
                        "component_ref": component_ref,
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "categories": sorted(found),
                    }
                )
            by_component[component_ref] = categories
        blockers.extend(
            _declared_import_blockers(
                registration.language,
                imported,
                packages,
                local_modules,
            )
        )
        expected = {
            component: {
                policy.category
                for policy in registration.inventory.dependency_policies
                if component in policy.component_refs
            }
            for component, _role in registration.inventory.component_roles
        }
        for component in sorted(expected):
            missing = expected[component] - by_component.get(component, set())
            unexpected = by_component.get(component, set()) - expected[component]
            blockers.extend(
                "missing_registered_category:" + component + ":" + value for value in sorted(missing)
            )
            blockers.extend(
                "unregistered_source_category:" + component + ":" + value for value in sorted(unexpected)
            )
        after = source_digest(project)
        if after != before:
            blockers.append("source_changed_during_analysis")
        value = {
            "schema_version": 1,
            "profile": "registered_static_workload_source_v1",
            "source_registration_id": registration.document()["source_registration_id"],
            "inventory_id": registration.inventory.document()["inventory_id"],
            "source_revision": before,
            "language": registration.language,
            "evaluated_at": self.clock().isoformat(),
            "status": "verified" if not blockers else "blocked",
            "blockers": sorted(set(blockers)),
            "runtime_packages": sorted(packages),
            "files": sorted(files, key=lambda item: (item["path"], item["component_ref"])),
            "execution_authorized": False,
        }
        digest = hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
        return {**value, "report_id": "WSI-" + digest}


def validate_static_source_inventory_report(registration, document):
    """Validate canonical persisted content, not the truth of the source scan."""
    from domain.environment_transition import _time
    from domain.workload_inventory import DEPENDENCY_CATEGORIES

    try:
        if not isinstance(registration, RegisteredStaticSourceInventory):
            raise TypeError("Registered static source inventory required")
        raw = json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if len(raw.encode()) > 512 * 1024:
            raise ValueError("Bounded static source inventory report required")
        expected_fields = {
            "schema_version",
            "profile",
            "source_registration_id",
            "inventory_id",
            "source_revision",
            "language",
            "evaluated_at",
            "status",
            "blockers",
            "runtime_packages",
            "files",
            "execution_authorized",
            "report_id",
        }
        if set(document) != expected_fields:
            raise ValueError("Unexpected static source inventory fields")
        registered = registration.document()
        if (
            document["schema_version"] != 1
            or document["profile"] != "registered_static_workload_source_v1"
            or document["source_registration_id"] != registered["source_registration_id"]
            or document["inventory_id"] != registered["inventory_id"]
            or document["source_revision"] != registered["source_revision"]
            or document["language"] != registered["language"]
            or document["execution_authorized"] is not False
            or document["status"] not in {"blocked", "verified"}
        ):
            raise ValueError("Static source report differs from registration")
        evaluated = datetime.fromisoformat(document["evaluated_at"])
        _time(evaluated)
        blockers = document["blockers"]
        packages = document["runtime_packages"]
        if (
            not isinstance(blockers, list)
            or blockers != sorted(set(blockers))
            or any(not isinstance(value, str) or not 1 <= len(value) <= 1200 for value in blockers)
            or (document["status"] == "verified") != (not blockers)
            or not isinstance(packages, list)
            or packages != sorted(set(packages))
            or len(packages) > 256
            or any(not isinstance(value, str) or not 1 <= len(value) <= 214 for value in packages)
        ):
            raise ValueError("Invalid static source report status or packages")
        assignments = {
            (component, path) for component, paths in registration.component_sources for path in paths
        }
        files = document["files"]
        if (
            not isinstance(files, list)
            or len(files) > 256
            or files != sorted(files, key=lambda item: (item["path"], item["component_ref"]))
        ):
            raise ValueError("Canonical static source file evidence required")
        for item in files:
            if (
                not isinstance(item, dict)
                or set(item) != {"path", "component_ref", "sha256", "categories"}
                or (item["component_ref"], item["path"]) not in assignments
                or not re.fullmatch(r"[a-f0-9]{64}", item["sha256"])
                or not isinstance(item["categories"], list)
                or item["categories"] != sorted(set(item["categories"]))
                or not set(item["categories"]) <= set(DEPENDENCY_CATEGORIES)
            ):
                raise ValueError("Invalid static source file evidence")
        if {(item["component_ref"], item["path"]) for item in files} != assignments:
            raise ValueError("Static source report does not cover its registration")
        if document["status"] == "verified":
            detected = {
                component: {
                    category
                    for item in files
                    if item["component_ref"] == component
                    for category in item["categories"]
                }
                for component, _role in registration.inventory.component_roles
            }
            expected = {
                component: {
                    policy.category
                    for policy in registration.inventory.dependency_policies
                    if component in policy.component_refs
                }
                for component, _role in registration.inventory.component_roles
            }
            if detected != expected:
                raise ValueError("Verified source categories differ from registration")
        unsigned = {key: value for key, value in document.items() if key != "report_id"}
        digest = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
        if document["report_id"] != "WSI-" + digest:
            raise ValueError("Static source report identity changed")
        return json.loads(raw)
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        raise ValueError("Invalid static source inventory report") from None
