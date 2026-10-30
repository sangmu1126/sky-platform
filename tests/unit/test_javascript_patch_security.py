import pytest

from application.patch_security import check_patch_security

JS = "app.get('/private', requireAuth, (req,res) => { return db.read(); });"
TS = "app.get('/private', requireAuth, (req: Request,res: Response) => { return db.read(); });"


@pytest.mark.parametrize("path,source", [("server.js", JS), ("server.ts", TS), ("server.tsx", JS)])
def test_guarded_async_database_repair_is_allowed(path, source):
    after = source.replace(" (req", " async (req").replace("return db.read()", "return await db.read()")
    check_patch_security(path, source, after)


@pytest.mark.parametrize(
    "candidate",
    [
        JS.replace("requireAuth, ", ""),
        JS.replace("requireAuth", "() => true"),
        "app.get('/private',(req,res)=>res.end('open'));" + JS,
        JS + "\nrequireAuth = () => true;",
        JS.replace("'/private'", "'/public'"),
        JS.replace("db.read()", "(requireAuth = ()=>true, db.read())"),
    ],
)
def test_guards_route_order_and_bindings_cannot_be_changed(candidate):
    with pytest.raises(ValueError, match="manual review"):
        check_patch_security("server.js", JS, candidate)


def test_await_on_authentication_cannot_be_removed_or_moved():
    before = "async function route(req) { if (!await verifyToken(req)) return 403; return db.read(); }"
    after = before.replace("await verifyToken", "verifyToken").replace("db.read()", "await db.read()")
    with pytest.raises(ValueError):
        check_patch_security("server.js", before, after)


@pytest.mark.parametrize("candidate", ["eval(input)", "new Function(input)", "child_process.exec(input)"])
def test_dynamic_execution_is_rejected(candidate):
    with pytest.raises(ValueError, match="dynamic execution"):
        check_patch_security("server.js", "const x = 1;", candidate)


def test_missing_parser_or_malformed_source_never_falls_back_to_regex():
    with pytest.raises(ValueError, match="parseable"):
        check_patch_security("server.ts", "const x = 1;", "const = ((((")
