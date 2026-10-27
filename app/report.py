import html, json
from .scanner import PROFILES
def _f(f, i):
    return (f"[{i}] Finding: {f['title']}\n  Affected target: {f['host']} {f['port']}/{f['proto']} ({f['service']})\n  Evidence: {f['evidence']}\n  Assessment: {f['assessment']}\n  Why it matters: {f['why']}\n"
            f"  Applicability: {f['applicability']}\n  Potential impact: {f['impact']}\n  How to fix: {f['fix']}\n  Safe next validation step: {f['next_step']}\n  References: {', '.join(f['refs']) or 'n/a'}\n  Severity: {f['severity']} | Confidence: {f['confidence']} (severity and confidence are separate)\n")
def text(scan, res):
    cfg = res.get("config", {}); L = [f"SURFACEWATCH ASSESSMENT {scan['id']}", f"Status: {scan['status']}", f"Started: {scan['created']}  Finished: {scan['finished']}", f"Target: {scan['target']} (resolved: {', '.join(res.get('ips', []))})",
         f"Profile: {scan['profile']} - {PROFILES.get(scan['profile'],{}).get('label','')}", f"Scan options: {json.dumps(cfg)}", f"Nmap command: {res.get('command','')}", "", "== HOSTS, PORTS, SERVICES =="]
    for h in res.get("hosts", []):
        L.append(f"Host {h['address']} {','.join(h['hostnames'])} [{h['state']}] OS: {', '.join(o['name'] for o in h['os']) or 'unknown'}")
        for p in h["ports"]: L.append(f"  {p['port']}/{p['proto']} {p['state']} {p['service']} {p['product']} {p['version']} {p['extrainfo']} cpe={','.join(p['cpes']) or 'none'} method={p['method']} conf={p['conf']}" + ("  (UDP open|filtered is inconclusive)" if p["state"] == "open|filtered" else ""))
    if not res.get("hosts"): L.append("No hosts reported up (host may be down, filtered, or discovery blocked; try 'skip discovery' on authorized hosts).")
    fs = res.get("findings", []); L += ["", f"== PROTOCOL / CONFIGURATION FINDINGS ({len(fs)}) =="] + [_f(f, i + 1) for i, f in enumerate(fs)] + ([] if fs else ["None generated from the evidence collected. This is not proof of absence."])
    cv = res.get("cves", []); L += ["", f"== CVE CANDIDATES ({len(cv)}) - candidates, NOT confirmed vulnerabilities =="]
    for c in cv[:100]: L.append(f"{c['id']} {c['host']}:{c['port']} CVSS={(c['cvss'] or {}).get('score')} EPSS={c['epss']} KEV={c['kev']} exploit-refs={len(c['exploit_refs'])} | {c['applicability']} | confidence {c['confidence']} | risk {c['risk']['severity']} ({c['risk']['score']})\n   Rationale: {c['rationale']}\n   {c['description'][:300]}")
    en = res.get("enrichment"); L += ["", "== ENRICHMENT STATUS =="]
    if en:
        L.append(f"Overall: {en['status']}  Sources: {json.dumps(en['sources'])}")
        for s in en["services"]: L.append(f"  {s['host']}:{s['port']}/{s['proto']} {s['product']} {s['version'] or '?'} -> {s['status']} {s.get('note','')} attempts={[(a['strategy'], a['outcome']) for a in s['attempts']]}")
    else: L.append("Enrichment did not run or did not complete. No conclusion about CVEs can be drawn.")
    L += ["", "== EXPLOITABILITY / CTI ==", "KEV listing, EPSS and exploit references (where shown above) are distinct claims: PoC existence, reported exploitation, KEV listing and exploitability in this environment are NOT equivalent. No exploit code was downloaded or run. No threat-actor attribution is made.",
          "", "== LIMITATIONS =="] + [f"- {x}" for x in res.get("warnings", []) + ["Scan is a point-in-time view from one vantage point.", "Advertised algorithms/protocols do not prove negotiation.", "Distribution backports can make upstream version matches false positives.", "Absence of findings/CVEs is not proof of security."]]
    L += ["", "== PIPELINE STAGES =="] + [f"  {k}: {v}" for k, v in res.get("stages", {}).items()] + (["", f"ERROR: {scan['error']}"] if scan.get("error") else [])
    return "\n".join(L) + "\n"
def to_html(t): return "<!doctype html><meta charset=utf-8><title>SurfaceWatch report</title><body style='font-family:monospace;max-width:1000px;margin:2em auto'><pre style='white-space:pre-wrap'>" + html.escape(t) + "</pre>"
def to_pdf(t):
    esc = lambda s: s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    lines = []
    for l in t.splitlines():
        while len(l) > 95: lines.append(l[:95]); l = l[95:]
        lines.append(l)
    pages = [lines[i:i + 60] for i in range(0, len(lines), 60)] or [[""]]; n = len(pages)
    objs = [b"<</Type/Catalog/Pages 2 0 R>>", ("<</Type/Pages/Kids[" + " ".join(f"{4+2*i} 0 R" for i in range(n)) + f"]/Count {n}>>").encode(), b"<</Type/Font/Subtype/Type1/BaseFont/Courier>>"]
    for i, pg in enumerate(pages):
        c = ("BT /F1 8 Tf 10 TL 36 806 Td\n" + "\n".join(f"({esc(l)}) Tj T*" for l in pg) + "\nET").encode("latin-1", "replace")
        objs.append(f"<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 842]/Resources<</Font<</F1 3 0 R>>>>/Contents {5+2*i} 0 R>>".encode())
        objs.append(b"<</Length %d>>stream\n" % len(c) + c + b"\nendstream")
    out, offs = b"%PDF-1.4\n", []
    for i, o in enumerate(objs): offs.append(len(out)); out += f"{i+1} 0 obj\n".encode() + o + b"\nendobj\n"
    x = len(out); out += f"xref\n0 {len(objs)+1}\n0000000000 65535 f \n".encode() + "".join(f"{o:010d} 00000 n \n" for o in offs).encode()
    return out + f"trailer<</Size {len(objs)+1}/Root 1 0 R>>\nstartxref\n{x}\n%%EOF".encode()
def compare(a, b):
    k = lambda r: {f"{h['address']}:{p['port']}/{p['proto']}": f"{p['service']} {p['product']} {p['version']}".strip() for h in r.get("hosts", []) for p in h["ports"] if p["state"] == "open"}
    fk = lambda r: {f"{f['host']}|{f['port']}/{f['proto']}|{f['title']}" for f in r.get("findings", [])}
    ck = lambda r: {f"{c['host']}:{c['port']}|{c['id']}" for c in r.get("cves", [])}
    A, B = k(a), k(b)
    return {"new_ports": sorted(set(B) - set(A)), "closed_ports": sorted(set(A) - set(B)), "changed_versions": {x: [A[x], B[x]] for x in A if x in B and A[x] != B[x]},
            "new_findings": sorted(fk(b) - fk(a)), "resolved_or_absent_findings": sorted(fk(a) - fk(b)), "unchanged_findings": sorted(fk(a) & fk(b)), "new_cve_candidates": sorted(ck(b) - ck(a)),
            "note": "Absence of a finding or closed port is not proof of remediation; revalidate the original condition."}
