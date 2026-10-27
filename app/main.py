import json, os, threading, uuid
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from . import analysis, db, intel, report, scanner, scope
LOCAL = ("127.0.0.1", "localhost", "[::1]", "::1")
STAGES = ["validate", "scan", "parse", "analyze", "enrich", "report"]
STATUSES = ["Detected", "Triaged", "Requires validation", "Validated", "False positive", "Accepted risk", "Remediation in progress", "Fixed", "Revalidated"]
app = FastAPI(title="SurfaceWatch CTI", version="1.0")
pool = ThreadPoolExecutor(max_workers=int(os.environ.get("SW_MAX_JOBS", 2))); RUN = {}; PENDING = []
db.init()
db.q("update scans set status='failed', error='Interrupted by server restart', finished=? where status in ('queued','running')", (db.now(),))
@app.middleware("http")
async def guard(req: Request, call_next):  # localhost-only + CSRF-style origin check
    if req.headers.get("host", "").rsplit(":", 1)[0] not in LOCAL and os.environ.get("SW_ALLOW_REMOTE") != "1": return JSONResponse({"error": "Host not allowed"}, 403)
    o = req.headers.get("origin")
    if req.method not in ("GET", "HEAD") and o and urlparse(o).hostname not in ("127.0.0.1", "localhost", "::1"): return JSONResponse({"error": "Cross-origin request blocked"}, 403)
    resp = await call_next(req); resp.headers["Cache-Control"] = "no-store"; return resp
class ScanReq(BaseModel):
    target: str = Field(max_length=253); profile: str = "standard"; skip_discovery: bool = False; os_detect: bool = False
    timing: int = Field(3, ge=1, le=4); max_rate: int = Field(0, ge=0, le=2000); host_timeout: int = Field(1800, ge=60, le=7200); authorized: bool = False; enrich: bool = True
class StateReq(BaseModel): key: str; status: str; owner: str = ""; notes: str = ""
def err(code, msg): raise HTTPException(code, {"error": msg})
@app.get("/api/v1/health")
def health():
    return {"status": "ok", "nmap": scanner.nmap_path(), "root": hasattr(os, "geteuid") and os.geteuid() == 0, "nvd_api_key": bool(os.environ.get("NVD_API_KEY")), 
            "profiles": {k: v["label"] for k, v in scanner.PROFILES.items()}, "script_allowlist": scanner.SCRIPT_ALLOW, "max_hosts": scope.max_hosts()}
@app.get("/api/v1/scopes")
def scopes(): return db.q("select * from scopes")
@app.post("/api/v1/validate")
def validate(r: ScanReq):
    try: return scope.validate(r.target, r.authorized)
    except scope.ScopeError as e: err(422, str(e))
@app.post("/api/v1/scans")
def create(r: ScanReq):
    if not scanner.nmap_path(): err(503, "Nmap is not installed (sudo apt install nmap)")
    if r.profile not in scanner.PROFILES: err(422, "Unknown profile")
    try: v = scope.validate(r.target, r.authorized); scanner.build_cmd(r.profile, v["nmap_targets"], r.skip_discovery, r.os_detect, r.timing, r.max_rate, r.host_timeout)
    except (scope.ScopeError, ValueError) as e: err(422, str(e))
    if len(PENDING) >= 6: err(429, "Too many queued/running scans")
    sid = uuid.uuid4().hex[:12]
    db.q("insert into scans(id,target,profile,status,created,config,stages,operator) values(?,?,?,?,?,?,?,?)", (sid, r.target, r.profile, "queued", db.now(), r.model_dump_json(), json.dumps({s: "pending" for s in STAGES}), "local-operator"))
    db.audit("scan.create", f"{sid} {r.target} {r.profile} external={v['external']}"); PENDING.append(sid); pool.submit(job, sid); return {"id": sid, "resolved": v["ips"]}
def _job(sid):
    s = db.q("select * from scans where id=?", (sid,), one=True); cfg = json.loads(s["config"]); st = json.loads(s["stages"]); holder = RUN[sid] = {}
    res = {"config": cfg, "hosts": [], "findings": [], "cves": [], "warnings": []}; status = "completed"; error = None; xml = None
    def stage(n, v): st[n] = v; db.q("update scans set stages=?, status=? where id=?", (json.dumps(st), "running", sid))
    try:
        stage("validate", "running"); v = scope.validate(cfg["target"], cfg["authorized"]); res["ips"] = v["ips"]; stage("validate", "ok")  # re-resolved now
        stage("scan", "running"); cmd = scanner.build_cmd(s["profile"], v["nmap_targets"], cfg["skip_discovery"], cfg["os_detect"], cfg["timing"], cfg["max_rate"], cfg["host_timeout"]); res["command"] = " ".join(cmd)
        xml, stderr, rc = scanner.run(cmd, cfg["host_timeout"] + 120, holder)
        if rc != 0 and not xml.strip(): raise RuntimeError(f"Nmap failed (rc={rc}): {stderr.strip()[:500]}")
        db.q("update scans set raw_xml=? where id=?", (xml, sid)); stage("scan", "ok")
        stage("parse", "running"); p = scanner.parse(xml); res["hosts"] = p["hosts"]; res["warnings"] += p["warnings"]; stage("parse", "ok" if not p["warnings"] else "warning")
    except Exception as e:
        status = "cancelled" if isinstance(e, InterruptedError) else "failed"; error = f"{type(e).__name__}: {e}"
        for k in STAGES:
            if st[k] in ("running", "pending"): st[k] = "failed" if st[k] == "running" else "skipped"
    if status == "completed":
        try: stage("analyze", "running"); res["findings"] = analysis.analyze(res["hosts"]); stage("analyze", "ok")
        except Exception as e: st["analyze"] = "failed"; status = "completed_with_errors"; error = f"Analysis failed: {e}"
        if cfg["enrich"]:
            try:
                stage("enrich", "running"); intel.enrich(res); st["enrich"] = "ok" if res["enrichment"]["status"] == "ok" else "partial"
                if st["enrich"] == "partial" and status == "completed": status = "completed_with_errors"; error = "Enrichment incomplete: some lookups failed. See report."
            except Exception as e: st["enrich"] = "failed"; status = "completed_with_errors"; error = f"Enrichment failed: {e}"
        else: st["enrich"] = "skipped"
    res["stages"] = st; st["report"] = "ok"
    db.q("update scans set status=?, finished=?, error=?, stages=?, result=? where id=?", (status, db.now(), error, json.dumps(st), json.dumps(res), sid)); RUN.pop(sid, None)
    if sid in PENDING: PENDING.remove(sid)
def job(sid):
    try: _job(sid)
    except Exception as e: db.q("update scans set status='failed', finished=?, error=? where id=?", (db.now(), f"Internal error: {type(e).__name__}: {e}", sid))
    finally:
        RUN.pop(sid, None)
        if sid in PENDING: PENDING.remove(sid)
def get_scan(sid):
    s = db.q("select * from scans where id=?", (sid,), one=True)
    if not s: err(404, "Scan not found")
    return s
@app.get("/api/v1/scans")
def scans(): return [{k: r[k] for k in ("id", "target", "profile", "status", "created", "finished", "error", "stages")} for r in db.q("select * from scans order by created desc limit 200")]
@app.get("/api/v1/scans/{sid}")
def scan(sid: str):
    s = get_scan(sid); s["result"] = json.loads(s["result"]) if s["result"] else None; s["stages"] = json.loads(s["stages"]); s.pop("raw_xml"); return s
@app.post("/api/v1/scans/{sid}/cancel")
def cancel(sid: str):
    h = RUN.get(sid)
    if not h: err(409, "Scan is not running")
    h["cancel"] = True
    if h.get("proc"): h["proc"].kill()
    db.audit("scan.cancel", sid); return {"ok": True}
@app.get("/api/v1/scans/{sid}/raw")
def raw(sid: str): return Response(get_scan(sid)["raw_xml"] or "", media_type="application/xml")
@app.get("/api/v1/scans/{sid}/report")
def rep(sid: str, fmt: str = "txt"):
    s = get_scan(sid); res = json.loads(s["result"]) if s["result"] else {}; t = report.text(s, res)
    if fmt == "txt": return PlainTextResponse(t, headers={"Content-Disposition": f"inline; filename=surfacewatch-{sid}.txt"})
    if fmt == "html": return Response(report.to_html(t), media_type="text/html")
    if fmt == "json": return JSONResponse({"scan": {k: s[k] for k in ("id", "target", "profile", "status", "created", "finished", "error")}, "result": res})
    if fmt == "pdf": return Response(report.to_pdf(t), media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=surfacewatch-{sid}.pdf"})
    err(422, "fmt must be txt|html|json|pdf")
@app.get("/api/v1/compare")
def compare(a: str, b: str):
    ra, rb = (json.loads(get_scan(x)["result"] or "{}") for x in (a, b)); return report.compare(ra, rb)
@app.get("/api/v1/state")
def states(): return db.q("select * from state")
@app.post("/api/v1/state")
def set_state(s: StateReq):
    if s.status not in STATUSES: err(422, f"status must be one of {STATUSES}")
    db.q("insert or replace into state values(?,?,?,?,?)", (s.key, s.status, s.owner, s.notes, db.now())); db.audit("finding.state", f"{s.key} -> {s.status}"); return {"ok": True}
@app.get("/api/v1/dashboard")
def dash():
    rows = [json.loads(r["result"]) for r in db.q("select result from scans where result is not null")]; sv = {}; ports = {"tcp": 0, "udp": 0}; hosts = set(); sev = {}; vers = set(); fails = 0; kev = 0; cand = 0
    for r in rows:
        for h in r.get("hosts", []):
            hosts.add(h["address"])
            for p in h["ports"]:
                if p["state"] == "open": ports[p["proto"]] = ports.get(p["proto"], 0) + 1; sv[p["service"]] = 1; (vers.add(f"{p['product']} {p['version']}") if p["version"] else 0)
        for f in r.get("findings", []): sev[f["severity"]] = sev.get(f["severity"], 0) + 1
        cand += len(r.get("cves", [])); kev += sum(1 for c in r.get("cves", []) if c["kev"]); fails += 1 if r.get("enrichment", {}).get("status") == "partial" else 0
    return {"scans": db.q("select count(*) n from scans", one=True)["n"], "hosts": len(hosts), "open_tcp": ports["tcp"], "open_udp": ports["udp"], "services": len(sv), "versions": len(vers), "cve_candidates": cand, "kev": kev, "enrichment_failures": fails,
            "findings_by_severity": sev, "validated": db.q("select count(*) n from state where status in ('Validated','Revalidated')", one=True)["n"]}
@app.get("/api/v1/audit")
def aud(): return db.q("select * from audit order by ts desc limit 200")
@app.get("/")
def idx(): return FileResponse(os.path.join(os.path.dirname(__file__), "..", "static", "index.html"))
