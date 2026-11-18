"""Local operator proof view. Never a hosted/public authentication boundary.

Backend is a fixed operator registration, not parameters from a browser. This
view exposes no mutation endpoint and never returns the backend's raw objects.
"""

import hmac
import ipaddress
import json
import math
import re
import secrets
from datetime import datetime
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler
from threading import BoundedSemaphore

ENVIRONMENTS = {"aws", "onprem", "unknown"}
OPERATION_KINDS = {"environment_copy", "environment_transfer", "environment_recover"}
OPERATION_STATUSES = {"queued", "running", "succeeded", "failed", "needs_attention"}

HTML = """<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sky · 환경 이전 검증</title>
<style>body{margin:0;background:#f5f7fb;color:#192438;font:16px -apple-system,BlinkMacSystemFont,sans-serif}main{max-width:1080px;margin:64px auto;padding:0 24px}header{display:flex;justify-content:space-between;align-items:center}h1{font-size:32px;letter-spacing:-1px}small,.muted{color:#68788b}button{border:0;border-radius:12px;background:#2873f5;color:white;padding:14px 20px;font:inherit;cursor:pointer}button:disabled{opacity:.6;cursor:wait}.data-table{max-height:320px;overflow:auto}.data-table th{position:sticky;top:0;background:white}#operations{max-height:320px;overflow:auto}.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin:26px 0}.card{background:white;border:1px solid #e7ebf2;border-radius:22px;padding:28px;box-shadow:0 5px 22px #243c5d05}.value{font-size:30px;font-weight:700;margin:14px 0}.label{font-weight:600;font-size:14px;color:#6d7d91}.route{padding:20px;background:#edf4ff;border-radius:14px;color:#2463c8}.badge{padding:6px 10px;background:#edf4ff;border-radius:8px;display:inline-block;font-size:13px}table{width:100%;border-collapse:collapse}td,th{text-align:left;border-bottom:1px solid #eef1f6;padding:12px 5px}th{color:#718097;font-size:13px}#error{color:#bb3c43}.note{font-size:14px;line-height:1.8}.row{display:flex;justify-content:space-between;gap:16px;padding:12px 0;border-bottom:1px solid #eef1f6}@media(max-width:720px){main{margin-top:24px}.grid{grid-template-columns:1fr}h1{font-size:26px}}</style>
<main><header><div><small>SKY / BEYOND LOCK-IN</small><h1>실행 환경이 바뀌어도, 데이터는 그대로</h1></div><button id="refresh">새로 확인</button></header>
<p class="muted">실제 AWS ↔ Linux VM 이전의 관측과 검증 기록</p><div class="route">같은 linux/arm64 이미지 · 같은 사설 HTTPS 진입점 · 쓰기 중지 후 데이터 동기화</div>
<div class="grid"><section class="card"><div class="label">현재 응답하는 환경</div><div class="value" id="environment">확인 중</div><span class="badge" id="availability">관측 대기</span><p class="muted" id="checked"></p></section><section class="card"><div class="label">현재 앱의 쓰기 상태</div><div class="value" id="writes">확인 중</div><p class="muted" id="dataCount">데이터를 직접 조회하고 있습니다.</p></section></div>
<section class="card"><h2>쓰기 보존 시험</h2><p class="note muted">실제 이전·복귀 동안 보낸 합성 요청의 과거 실측입니다. 최대 응답 간격은 샘플링·네트워크 시간을 포함하며 무중단 또는 SLA를 뜻하지 않습니다.</p><div id="continuity">검증 기록 확인 중</div></section><br><section class="card"><h2>검증된 실행 기록</h2><p class="note muted">과거 실측과 현재 상태를 구분합니다. 대상 DB·앱과 이미지를 준비한 뒤 측정한 전환 시간이며, 최대 중단 시간 보장이 아닙니다.</p><div id="history"></div></section>
<div class="grid"><section class="card"><h2>앱 데이터</h2><p class="muted note">이전 검증용 합성 점수 데이터 · 최대 100개 표시</p><div class="data-table"><table><thead><tr><th>ID</th><th>점수</th></tr></thead><tbody id="scores"></tbody></table></div></section><section class="card"><h2>영속 작업 상태</h2><p class="note muted">실패를 성공으로 바꾸지 않고 복구 작업을 별도로 남깁니다.</p><div id="operations"></div></section></div>
<section class="card"><h2>아직 검증하지 않은 범위</h2><p class="note">일반 사용자 API/SQS 전체 연결, 모든 보존 조건, 임의 앱의 쓰기 제어, CDC 및 WebSocket 세션 이전은 별도 완료 기준입니다. 실제 AI 모델 평가는 키 없이 보류 중입니다.</p><span class="badge">운영자 검증 경로</span> <span class="badge">무중단 보장 없음</span> <span class="badge">공개 인터넷 주소 아님</span></section><p id="error"></p></main><script src="/demo.js"></script></html>"""
JS = """const names={aws:'AWS Fargate + RDS',onprem:'Linux VM + PostgreSQL',unknown:'현재 상태 미확인'};const kinds={environment_copy:'대상 데이터 준비',environment_transfer:'환경 이전',environment_recover:'데이터 복구·복귀'};const states={queued:'대기',running:'실행 중',succeeded:'완료',failed:'실패',needs_attention:'조정 필요'};
function text(id,value){document.getElementById(id).textContent=value;}function row(parent,left,right){const e=document.createElement('div');e.className='row';const a=document.createElement('span'),b=document.createElement('strong');a.textContent=left;b.textContent=right;e.append(a,b);parent.append(e);}
async function refresh(){const button=document.getElementById('refresh');if(button.disabled)return;button.disabled=true;try{const response=await fetch('/api/status',{cache:'no-store',credentials:'same-origin'});if(!response.ok)throw new Error('현재 상태를 확인할 수 없습니다.');const d=await response.json();text('environment',names[d.active_environment]);text('availability',d.app_available?'실제 HTTPS 응답 확인':'현재 응답 미확인');text('checked','확인 시각 '+new Date(d.checked_at).toLocaleString('ko-KR',{timeZone:'Asia/Seoul'})+' KST');text('writes',d.writes_blocked===null?'미확인':d.writes_blocked?'쓰기 중지':'쓰기 가능');text('dataCount','표시된 데이터 '+d.rows.length+'개');for(const id of ['scores','history','operations'])document.getElementById(id).replaceChildren();for(const v of d.rows){const tr=document.createElement('tr');for(const n of v){const td=document.createElement('td');td.textContent=n;tr.append(td);}document.getElementById('scores').append(tr);}for(const v of d.history)row(document.getElementById('history'),v.label,v.seconds.toFixed(1)+'초 · '+v.outcome);for(const v of d.operations)row(document.getElementById('operations'),kinds[v.kind],states[v.status]);const continuity=document.getElementById('continuity');continuity.replaceChildren();if(d.continuity){row(continuity,'승인된 쓰기 / VM에서 승인된 쓰기',d.continuity.acknowledged_writes+'건 / '+d.continuity.acknowledged_vm_writes+'건');row(continuity,'복귀 후 승인된 쓰기 유실',d.continuity.acknowledged_writes_lost+'건');row(continuity,'계획된 쓰기 일시 중지 응답',d.continuity.planned_pause_responses+'회');row(continuity,'관측된 최대 쓰기 응답 간격',d.continuity.max_observed_ack_gap_seconds.toFixed(1)+'초');row(continuity,'시험 실행 권한',d.continuity.scoped_sql_roles?'앱별 제한 DB 역할':'기존 운영자 DB 역할');}else{continuity.textContent='확인된 쓰기 보존 시험 기록 없음';}text('error',d.app_available?'':'현재 관측 실패입니다. 과거 성공 기록을 현재 성공으로 표시하지 않습니다.');}catch(e){text('environment',names.unknown);text('availability','현재 응답 미확인');text('writes','미확인');text('checked','현재 관측 시각 미확인');text('dataCount','현재 데이터 미확인');for(const id of ['scores','operations'])document.getElementById(id).replaceChildren();text('error','현재 상태 조회 실패. 자동 변경이나 재시도는 실행하지 않습니다.');}finally{button.disabled=false;}}document.getElementById('refresh').addEventListener('click',refresh);refresh();"""


def public_snapshot(value):
    """Allow only explicit synthetic operational fields, never raw backend JSON."""
    if not isinstance(value, dict):
        raise TypeError("Typed demo projection required")
    environment = value.get("active_environment", "unknown")
    available = value.get("app_available") is True
    blocked = value.get("writes_blocked")
    if environment not in ENVIRONMENTS or (blocked is not None and type(blocked) is not bool):
        raise ValueError("Invalid observation")
    if not available:
        environment, blocked = "unknown", None
    rows = value.get("rows", [])
    if (
        not isinstance(rows, list)
        or len(rows) > 100
        or any(
            not isinstance(row, (tuple, list))
            or len(row) != 2
            or any(type(v) is not int or abs(v) >= 2**63 for v in row)
            for row in rows
        )
    ):
        raise ValueError("Bounded synthetic score rows required")
    history = []
    for item in value.get("history", [])[:8]:
        label = item.get("label")
        seconds = item.get("seconds")
        outcome = item.get("outcome")
        if (
            label
            not in {
                "AWS → VM",
                "VM → AWS",
                "DB 리스 복구",
                "DB 리스 이전",
                "DB 리스 복귀",
                "제한 역할 이전",
                "제한 역할 복귀",
                "재시작 후 이전",
                "재시작 후 복귀",
                "최근 시연 이전",
                "최근 시연 복귀",
            }
            or type(seconds) not in {float, int}
            or not math.isfinite(seconds)
            or not 0 <= seconds <= 3600
            or outcome not in {"검증됨", "안전 정지 후 복구"}
        ):
            raise ValueError("Invalid proof summary")
        history.append({"label": label, "seconds": seconds, "outcome": outcome})
    operations = []
    for item in value.get("operations", [])[:10]:
        if item.get("kind") not in OPERATION_KINDS or item.get("status") not in OPERATION_STATUSES:
            raise ValueError("Invalid operation projection")
        operations.append({"kind": item["kind"], "status": item["status"]})
    checked = value.get("checked_at", "")
    if not isinstance(checked, str) or len(checked) > 40:
        raise ValueError("Bounded timestamp required")
    if datetime.fromisoformat(checked).tzinfo is None:
        raise ValueError("Timezone-aware observation required")
    continuity = value.get("continuity")
    if continuity is not None:
        counts = (
            "acknowledged_writes",
            "acknowledged_vm_writes",
            "acknowledged_writes_lost",
            "planned_pause_responses",
        )
        if not isinstance(continuity, dict) or any(
            type(continuity.get(k)) is not int or not 0 <= continuity[k] <= 1000000 for k in counts
        ):
            raise ValueError("Bounded synthetic continuity counters required")
        gap = continuity.get("max_observed_ack_gap_seconds")
        if (
            type(gap) not in {int, float}
            or not math.isfinite(gap)
            or not 0 <= gap <= 3600
            or type(continuity.get("scoped_sql_roles")) is not bool
            or continuity["acknowledged_vm_writes"] > continuity["acknowledged_writes"]
            or continuity["acknowledged_writes_lost"] > continuity["acknowledged_writes"]
        ):
            raise ValueError("Qualified continuity measurements required")
        continuity = {k: continuity[k] for k in (*counts, "max_observed_ack_gap_seconds", "scoped_sql_roles")}
    return {
        "continuity": continuity,
        "active_environment": environment,
        "app_available": available,
        "writes_blocked": blocked,
        "rows": rows if available else [],
        "checked_at": checked,
        "history": history,
        "operations": operations,
        "scope": "operator_qualification_only",
        "full_v4_complete": False,
        "model_evaluated": False,
    }


def handler_for_environment_demo(snapshot, *, session_token=None):
    token = session_token or secrets.token_urlsafe(32)
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", token):
        raise ValueError("Private operator session required")
    observation_slot = BoundedSemaphore(1)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def reply(self, status, body, kind="application/json", *, cookie=False):
            raw = body.encode() if isinstance(body, str) else json.dumps(body, allow_nan=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", kind + "; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
            )
            if cookie:
                self.send_header(
                    "Set-Cookie", "sky_env_demo=" + token + "; HttpOnly; SameSite=Strict; Path=/"
                )
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            address, port = self.server.server_address[:2]
            expected_host = f"{address}:{port}"
            if (
                not ipaddress.ip_address(address).is_loopback
                or self.headers.get("Host") != expected_host
                or self.headers.get("Origin") not in {None, "http://" + expected_host}
                or self.headers.get("Sec-Fetch-Site") not in {None, "same-origin", "same-site", "none"}
            ):
                return self.reply(403, {"error": "denied"})
            if self.path == "/":
                return self.reply(200, HTML, "text/html", cookie=True)
            if self.path == "/demo.js":
                return self.reply(200, JS, "application/javascript")
            if self.path != "/api/status":
                return self.reply(404, {"error": "not_found"})
            cookies = SimpleCookie()
            try:
                cookies.load(self.headers.get("Cookie", ""))
            except CookieError:
                return self.reply(403, {"error": "denied"})
            supplied = cookies.get("sky_env_demo")
            if (
                supplied is None
                or not supplied.value.isascii()
                or not hmac.compare_digest(supplied.value, token)
            ):
                return self.reply(403, {"error": "denied"})
            if not observation_slot.acquire(blocking=False):
                return self.reply(429, {"error": "observation_already_running"})
            try:
                try:
                    projection = public_snapshot(snapshot())
                except Exception:  # noqa: BLE001 -- backend/provider diagnostics may contain credentials
                    return self.reply(503, {"error": "observation_unavailable"})
            finally:
                observation_slot.release()
            return self.reply(200, projection)

        def do_POST(self):
            self.reply(405, {"error": "read_only_operator_view"})

    return Handler
