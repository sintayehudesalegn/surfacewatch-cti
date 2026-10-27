"""Target validation + authorization. Fails closed."""
import ipaddress, os, re, socket
from . import db
HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", re.I)
class ScopeError(ValueError): pass
def max_hosts(): return int(os.environ.get("SW_MAX_HOSTS", 256))
def classify(ip):
    if ip.is_multicast or ip.is_unspecified or ip.is_reserved or ip.is_link_local: return "prohibited"  # incl. 169.254.169.254
    if ip.is_loopback or ip.is_private: return "private"
    return "public"
def parse_target(t):
    t = (t or "").strip()
    if not t or len(t) > 253 or not re.fullmatch(r"[A-Za-z0-9.:/_-]+", t): raise ScopeError("Invalid target syntax")
    try: return "net", ipaddress.ip_network(t, strict=False)
    except ValueError: pass
    if HOST_RE.match(t) and not t.replace(".", "").isdigit(): return "host", t.lower()
    raise ScopeError("Invalid target syntax")
def resolve(host):
    try: infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e: raise ScopeError(f"DNS resolution failed: {e}")
    ips = sorted({ipaddress.ip_address(i[4][0].split("%")[0]) for i in infos}, key=str)
    if not ips: raise ScopeError("Hostname did not resolve")
    return ips
def record(kind, val):
    v, k = str(val), ("cidr" if kind == "net" else "domain")
    if not db.q("select 1 from scopes where value=?", (v,), one=True):
        db.q("insert into scopes(kind,value,note) values(?,?,?)", (k, v, "authorized at scan time")); db.audit("asset.authorized", v)
def validate(target, authorized=False, resolver=resolve):
    """Run at create AND at execution time (DNS-rebinding defence)."""
    kind, val = parse_target(target)
    if kind == "net":
        if val.num_addresses > max_hosts(): raise ScopeError(f"Range too large (max {max_hosts()} addresses)")
        probe = [val.network_address, val[-1]]; nm = [str(val)]
    else:
        probe = resolver(val); nm = [str(i) for i in probe]
    cls = {classify(i) for i in probe}
    if "prohibited" in cls: raise ScopeError("Target includes a prohibited address (link-local, cloud metadata, multicast, reserved, unspecified)")
    if not authorized: raise ScopeError("Confirm that you own this asset or have written authorization to test it")
    record(kind, val)
    return {"kind": kind, "ips": [str(i) for i in probe], "nmap_targets": nm, "external": "public" in cls}
