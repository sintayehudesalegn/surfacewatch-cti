import os, sys, tempfile, unittest
os.environ["SW_DB"] = tempfile.mktemp(suffix=".db"); sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from app import analysis, db, report, scanner, scope  # noqa
XML = """<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><hostnames><hostname name="lab.example"/></hostnames><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="6.6.1p1" extrainfo="Ubuntu 2ubuntu2.13" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:6.6.1p1</cpe></service>
<script id="ssh2-enum-algos" output="kex_algorithms: (2)&#10;diffie-hellman-group1-sha1&#10;curve25519-sha256"/></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="http" tunnel="ssl"/><script id="ssl-enum-ciphers" output="  TLSv1.0:&#10;    least strength: C"/><script id="ssl-cert" output="Subject: commonName=a&#10;Issuer: commonName=a&#10;Not valid after:  2020-01-01T00:00:00"/></port>
<port protocol="udp" portid="161"><state state="open|filtered"/><service name="snmp"/></port><port protocol="tcp" portid="6379"><state state="open"/><service name="redis"/></port></ports></host><runstats><finished/></runstats></nmaprun>"""
class T(unittest.TestCase):
    def setUp(self): db.init(); db.q("delete from scopes"); db.q("delete from settings")
    def test_parse(self):
        r = scanner.parse(XML); p = r["hosts"][0]["ports"]; self.assertEqual(len(p), 4); self.assertEqual(p[0]["cpes"], ["cpe:/a:openbsd:openssh:6.6.1p1"]); self.assertEqual(p[2]["state"], "open|filtered"); self.assertEqual(p[2]["cpes"], [])
    def test_invalid_xml(self): self.assertRaises(ValueError, scanner.parse, "<nmaprun><host>")
    def test_rules(self):
        t = [f["title"] for f in analysis.analyze(scanner.parse(XML)["hosts"])]
        self.assertIn("Legacy SSH algorithms advertised", t); self.assertIn("Deprecated protocol TLSv1.0 supported", t); self.assertIn("TLS certificate expired", t); self.assertIn("Self-signed certificate observed", t); self.assertTrue(any("Redis" in x for x in t))
        self.assertFalse(any("SMB" in x for x in t))  # no evidence -> no finding
    def test_fingerprint_no_cpe(self):
        f = analysis.fingerprint({"product": "Apache httpd", "version": "2.4.7", "extrainfo": "(Ubuntu)", "cpes": []}); self.assertEqual((f["vendor"], f["pname"], f["version"], f["distro"]), ("apache", "http_server", "2.4.7", "Ubuntu"))
        self.assertEqual(analysis.fingerprint({"product": "OpenSSH", "version": "6.6.1p1"})["update"], "p1")
    def test_scope(self):
        ip = __import__("ipaddress").ip_address; pub = lambda h: [ip("93.184.216.34")]
        for bad in ["", "a b", "1.2.3.4;rm -rf /", "$(id)", "x" * 300, "`id`", "a|b"]: self.assertRaises(scope.ScopeError, scope.validate, bad, True)
        self.assertRaises(scope.ScopeError, scope.validate, "example.org", False, pub)  # no authorization confirmed
        self.assertTrue(scope.validate("example.org", True, pub)["external"]); self.assertEqual(db.q("select value from scopes")[0]["value"], "example.org")
        for h in ("169.254.169.254", "224.0.0.1", "0.0.0.0"): self.assertRaises(scope.ScopeError, scope.validate, "example.org", True, lambda x, h=h: [ip(h)])
        self.assertRaises(scope.ScopeError, scope.validate, "10.0.0.0/8", True)  # too large
        self.assertFalse(scope.validate("10.1.1.0/28", True)["external"]); self.assertEqual(scope.validate("127.0.0.1", True)["ips"], ["127.0.0.1", "127.0.0.1"])
    def test_cmd_safe(self):
        c = scanner.build_cmd("standard", ["192.0.2.1"]); self.assertIn("--", c); self.assertEqual(c[-1], "192.0.2.1"); self.assertNotIn("--script=vuln", c); self.assertRaises(ValueError, scanner.build_cmd, "x; id", ["a"])
    def test_report(self):
        r = scanner.parse(XML); r["findings"] = analysis.analyze(r["hosts"]); r["hosts"][0]["ports"][0]["product"] = "<script>alert(1)</script>"
        s = {"id": "t1", "status": "completed_with_errors", "created": "x", "finished": "y", "target": "lab", "profile": "standard", "error": "Enrichment failed"}
        t = report.text(s, r); self.assertIn("Enrichment did not run", t); self.assertIn("Safe next validation step", t); h = report.to_html(t); self.assertNotIn("<script>alert", h); self.assertTrue(report.to_pdf(t).startswith(b"%PDF"))
    def test_compare(self):
        a = scanner.parse(XML); b = scanner.parse(XML); b["hosts"][0]["ports"].pop(3); self.assertEqual(report.compare(a, b)["closed_ports"], ["192.0.2.10:6379/tcp"])
if __name__ == "__main__": unittest.main()
