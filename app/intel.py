"""NVD / CISA KEV / FIRST EPSS adapters with caching and honest failure reporting."""
import json, os, time, urllib.parse, urllib.request
from . import db
from .analysis import fingerprint, risk
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS = "https://api.first.org/data/v1/epss"
def http(url, params=None, headers=None, timeout=30):
    if params: url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "SurfaceWatch/1.0", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r: return json.loads(r.read().decode())
def cached(k, ttl, fn):
    r = db.q("select v,ts from cache where k=?", (k,), one=True)
    if r and time.time() - r["ts"] < ttl: return json.loads(r["v"])
    v = fn(); db.q("insert or replace into cache values(?,?,?)", (k, json.dumps(v), time.time())); return v
def nvd(params):
    key = os.environ.get("NVD_API_KEY")
    def f():
        time.sleep(0.7 if key else 6.5)  # NVD public rate limit: 5 req / 30 s without key
        return http(NVD, params, {"apiKey": key} if key else None)
    return cached("nvd:" + json.dumps(params, sort_keys=True), 86400, f)
def parse_cve(item):
    c = item["cve"]; m = c.get("metrics", {}); cv = None
    for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if m.get(k):
            d = m[k][0]["cvssData"]; cv = {"version": d.get("version"), "score": d.get("baseScore"), "vector": d.get("vectorString"), "severity": d.get("baseSeverity") or m[k][0].get("baseSeverity")}; break
    refs = c.get("references", [])
    return {"id": c["id"], "description": next((x["value"] for x in c.get("descriptions", []) if x["lang"] == "en"), ""), "cvss": cv, "published": c.get("published"), "modified": c.get("lastModified"),
            "references": [r["url"] for r in refs][:15], "exploit_refs": [r["url"] for r in refs if "Exploit" in r.get("tags", [])][:5], "kev": False, "epss": None, "epss_pct": None}
def cpe23(fp):
    v = f"{fp['version']}" + (f":{fp['update']}" if fp["update"] else "")
    return f"cpe:2.3:a:{fp['vendor']}:{fp['pname']}:{v}" + ("" if fp["update"] else ":*")
def match_service(host, p):
    fp = fingerprint(p); rec = {"host": host["address"], "port": p["port"], "proto": p["proto"], "product": fp["product"], "version": fp["version"], "attempts": [], "status": "skipped", "cves": []}
    if not fp["product"] or not fp["version"]:
        rec["note"] = "Product or version not identified; CVE matching skipped (not evidence of safety). Manually identify the software and check vendor advisories."; return rec
    tries = []
    for c in fp["cpes"]:
        parts = c.split(":")
        if c.startswith("cpe:/a:") and len(parts) >= 5 and parts[4]: tries.append(("cpe", {"virtualMatchString": c.replace("cpe:/a:", "cpe:2.3:a:", 1)}))
    if fp["vendor"]: tries.append(("vendor-product-version", {"virtualMatchString": cpe23(fp)}))
    tries.append(("keyword", {"keywordSearch": f"{fp['product']} {fp['version']}", "resultsPerPage": 20}))
    failed = False
    for name, prm in tries:
        try:
            d = nvd({**prm, "resultsPerPage": 100} if name != "keyword" else prm); items = d.get("vulnerabilities", [])
            rec["attempts"].append({"strategy": name, "query": prm, "outcome": "matches" if items else "empty response", "count": len(items)})
            if items:
                conf = "Low" if name == "keyword" else ("Low" if fp["distro"] else "Medium")
                for it in items:
                    cv = parse_cve(it); cv["strategy"] = name; cv["confidence"] = conf
                    cv["applicability"] = "Requires validation" if fp["distro"] else "Potential version match"
                    cv["rationale"] = (f"Fingerprint {fp['product']} {fp['version']}{fp['update'] or ''} matched an NVD candidate via {name}. " +
                        (f"Package looks {fp['distro']}-built: backported fixes can hide behind older upstream versions; check the distro security tracker and package revision before confirming. " if fp["distro"] else "Upstream version match only; patch status and exposure of the vulnerable feature are unverified. ") +
                        ("Keyword matching is broad and low-confidence." if name == "keyword" else ""))
                    rec["cves"].append(cv)
                rec["status"] = "ok"; break
        except Exception as e:
            failed = True; rec["attempts"].append({"strategy": name, "query": prm, "outcome": "failed", "detail": f"{type(e).__name__}: {e}"})
    if not rec["cves"]: rec["status"] = "failed" if failed else "empty"; rec["note"] = ("Lookup failed; absence of results is NOT evidence of safety." if failed else "Sources returned no candidates; this is not proof the software is free of vulnerabilities (CPE gaps, source lag, backports).")
    return rec
def enrich(result, progress=lambda m: None):
    en = {"status": "ok", "sources": {}, "services": []}; seen = {}
    for h in result["hosts"]:
        for p in h["ports"]:
            if p["state"] == "open": r = match_service(h, p); en["services"].append({k: v for k, v in r.items() if k != "cves"}); seen[(h["address"], p["port"], p["proto"])] = r["cves"]
    ids = sorted({c["id"] for v in seen.values() for c in v})
    kev, epss = set(), {}
    if ids:
        try: kev = {v["cveID"] for v in cached("kev", 43200, lambda: http(KEV, timeout=60))["vulnerabilities"]}; en["sources"]["cisa_kev"] = "ok"
        except Exception as e: en["sources"]["cisa_kev"] = f"failed: {e}"
        try:
            for i in range(0, len(ids), 50):
                ch = ids[i:i + 50]; d = cached("epss:" + ",".join(ch), 43200, lambda: http(EPSS, {"cve": ",".join(ch)}))
                for r in d.get("data", []): epss[r["cve"]] = (float(r["epss"]), float(r["percentile"]))
            en["sources"]["first_epss"] = "ok"
        except Exception as e: en["sources"]["first_epss"] = f"failed: {e}"
    cves = []
    for (a, port, pr), lst in seen.items():
        for c in lst:
            c.update(kev=c["id"] in kev, epss=epss.get(c["id"], (None, None))[0], epss_pct=epss.get(c["id"], (None, None))[1]); c.update(host=a, port=port, proto=pr)
            c["risk"] = risk({**c, "epss": c["epss"] or 0}, c["confidence"]); cves.append(c)
    cves.sort(key=lambda c: -c["risk"]["score"]); result["cves"] = cves
    sts = {s["status"] for s in en["services"]}
    en["sources"]["nvd"] = "failed for some/all lookups" if "failed" in sts else ("ok" if "ok" in sts or "empty" in sts else "not queried")
    if "failed" in sts or any(str(v).startswith("failed") for v in en["sources"].values()): en["status"] = "partial"
    result["enrichment"] = en
