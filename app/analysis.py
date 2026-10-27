"""Rule-based findings, product fingerprinting, risk scoring. Rules only fire on actual evidence."""
import re, datetime as dt
WEAK_SSH = {"diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1", "diffie-hellman-group14-sha1", "ssh-dss", "ssh-rsa", "3des-cbc", "arcfour", "arcfour128", "arcfour256",
            "aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc", "cast128-cbc", "hmac-md5", "hmac-md5-96", "hmac-sha1-96", "umac-64@openssh.com"}
EXPOSED = {23: ("Telnet", "Medium"), 2375: ("Docker API", "Medium"), 3389: ("RDP", "Low"), 5900: ("VNC", "Low"), 6379: ("Redis", "Low"), 27017: ("MongoDB", "Low"),
           3306: ("MySQL/MariaDB", "Low"), 5432: ("PostgreSQL", "Low"), 1433: ("MS SQL Server", "Low"), 9200: ("Elasticsearch", "Low"), 445: ("SMB", "Low"), 111: ("RPC portmapper", "Low")}
ALIASES = {"openssh": ("openbsd", "openssh"), "apache httpd": ("apache", "http_server"), "nginx": ("nginx", "nginx"), "vsftpd": ("vsftpd_project", "vsftpd"),
 "proftpd": ("proftpd", "proftpd"), "postfix": ("postfix", "postfix"), "exim": ("exim", "exim"), "mysql": ("oracle", "mysql"), "mariadb": ("mariadb", "mariadb"),
 "openssl": ("openssl", "openssl"), "samba": ("samba", "samba"), "isc bind": ("isc", "bind"), "redis": ("redis", "redis"), "mongodb": ("mongodb", "mongodb"),
 "postgresql": ("postgresql", "postgresql"), "dovecot": ("dovecot", "dovecot"), "lighttpd": ("lighttpd", "lighttpd"), "tomcat": ("apache", "tomcat"),
 "microsoft iis": ("microsoft", "internet_information_services"), "elasticsearch": ("elastic", "elasticsearch")}
def fingerprint(p):
    prod = (p.get("product") or "").strip(); text = f"{p.get('version','')} {p.get('extrainfo','')}"
    vendor = pname = None
    for k in sorted(ALIASES, key=len, reverse=True):
        if k in prod.lower(): vendor, pname = ALIASES[k]; break
    m = re.search(r"(\d+(?:\.\d+)+)(?:[ _-]?(p\d+))?", p.get("version") or "")
    distro = next((d for d in ("Ubuntu", "Debian", "Red Hat", "CentOS", "Fedora", "SUSE", "Alpine") if d.lower() in text.lower()), None)
    if not distro and re.search(r"\.el\d|ubuntu\d|deb\d+u\d", text, re.I): distro = "distribution-packaged"
    return {"product": prod, "vendor": vendor, "pname": pname, "version": m.group(1) if m else None, "update": m.group(2) if m else None, "distro": distro, "cpes": p.get("cpes", [])}
def mk(h, p, sev, conf, title, ev, assess, why, impact, fix, nxt, refs=(), kind="config", app="Observed configuration/exposure; this does not by itself establish a CVE."):
    return {"host": h["address"], "port": p["port"], "proto": p["proto"], "service": p["service"], "severity": sev, "confidence": conf, "title": title, "evidence": ev[:1500],
            "assessment": assess, "why": why, "applicability": app, "impact": impact, "fix": fix, "next_step": nxt, "refs": list(refs), "kind": kind}
def analyze(hosts, now=None):
    now = now or dt.date.today(); out = []
    for h in hosts:
        for p in h["ports"]:
            if p["state"] != "open": continue
            for s in p["scripts"]:
                o, i = s["output"], s["id"]
                if i == "ssl-enum-ciphers":
                    for pr in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"):
                        if re.search(rf"^\s*{re.escape(pr)}:", o, re.M):
                            out.append(mk(h, p, "High" if pr.startswith("SSL") else "Medium", "High", f"Deprecated protocol {pr} supported", o, f"The server answered handshakes for {pr}. Observed via ssl-enum-ciphers.",
                              "Deprecated protocols lack modern protections and fail current baselines (e.g. PCI DSS, NIST SP 800-52r2).", "Downgrade/weak-crypto exposure for clients that negotiate this protocol; not proof of a specific TLS CVE.",
                              f"Disable {pr}; allow TLS 1.2+ only; check client compatibility; rescan.", f"Confirm with: openssl s_client -connect {h['address']}:{p['port']} -{pr.lower().replace('tlsv','tls').replace('.','_')}  (only on authorized targets)", ["https://csrc.nist.gov/pubs/sp/800/52/r2/final"]))
                    m = re.search(r"least strength: ([A-F])", o)
                    if m and m.group(1) in "DEF":
                        out.append(mk(h, p, "Medium", "High", "Weak TLS cipher suites advertised", o, f"Nmap grades the weakest offered cipher {m.group(1)}. Advertised suites are not proof a client negotiated them.",
                          "Weak ciphers reduce confidentiality guarantees.", "Possible traffic decryption by a capable network attacker if a client negotiates the weak suite.", "Restrict to AEAD suites (AES-GCM/ChaCha20) with forward secrecy.", "Review server cipher config; rescan with ssl-enum-ciphers.", ["https://ssl-config.mozilla.org/"]))
                if i == "ssl-cert":
                    m = re.search(r"Not valid after:\s+(\d{4}-\d{2}-\d{2})", o)
                    if m and dt.date.fromisoformat(m.group(1)) < now:
                        out.append(mk(h, p, "Medium", "High", "TLS certificate expired", o, f"Certificate validity ended {m.group(1)}.", "Expired certificates cause trust failures and train users to ignore warnings.", "Service outage for strict clients; interception risk if users bypass warnings.", "Renew and deploy a new certificate; automate renewal.", "Check the served certificate chain after renewal.", []))
                    su, iu = re.search(r"Subject: (.*)", o), re.search(r"Issuer: (.*)", o)
                    if su and iu and su.group(1).strip() == iu.group(1).strip():
                        out.append(mk(h, p, "Low", "Medium", "Self-signed certificate observed", o, "Subject equals Issuer, so it is likely self-signed.", "Clients cannot validate it against a public trust chain.", "Weaker server-identity assurance.", "Use a certificate from a trusted CA (internal CA for private services).", "Confirm chain with openssl s_client -showcerts."))
                    b = re.search(r"Public Key bits:\s*(\d+)", o)
                    if b and int(b.group(1)) < 2048 and "rsa" in o.lower():
                        out.append(mk(h, p, "Medium", "High", f"RSA key below 2048 bits ({b.group(1)})", o, "Observed short RSA public key.", "Short RSA keys are within practical factoring range.", "Impersonation risk.", "Reissue with RSA >=2048 or ECDSA P-256.", "Verify certificate key size."))
                if i == "ssh2-enum-algos":
                    weak = sorted({t for t in re.split(r"[\s,]+", o) if t in WEAK_SSH})
                    if weak:
                        out.append(mk(h, p, "Low", "Medium", "Legacy SSH algorithms advertised", o, f"The server advertises: {', '.join(weak)}. The scan shows they are advertised, not that any client negotiated them.",
                          "Some are deprecated and may violate hardening baselines.", "Downgrade risk for clients that select them.", "Set explicit KexAlgorithms/Ciphers/MACs/HostKeyAlgorithms in sshd_config, drop legacy entries, verify clients, rescan.", "Run ssh-audit against the authorized host.", ["https://www.openssh.com/legacy.html"]))
                if i == "smb-protocols" and re.search(r"NT LM 0\.12|SMBv1", o):
                    out.append(mk(h, p, "High", "High", "SMBv1 dialect enabled", o, "The server offers the SMBv1 dialect (NT LM 0.12).", "SMBv1 is deprecated and was abused by wormable exploits (e.g. MS17-010).", "Exposure to legacy SMB attack classes if unpatched.", "Disable SMBv1 (Windows: Disable-WindowsOptionalFeature SMB1Protocol; Samba: server min protocol = SMB2).", "Confirm with nmap smb-protocols after change; check patch level.", ["https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"]))
                if (i == "smb2-security-mode" and "not required" in o) or (i == "smb-security-mode" and re.search(r"message_signing: (disabled|supported)", o)):
                    out.append(mk(h, p, "Medium", "High", "SMB signing not required", o, "Signing is not enforced.", "Unsigned SMB sessions permit relay/tampering.", "NTLM relay in the presence of other conditions.", "Require SMB signing via GPO / smb.conf 'server signing = mandatory'.", "Recheck with smb2-security-mode."))
                if i == "http-methods":
                    m = re.search(r"Potentially risky methods:\s*(.*)", o)
                    if m: out.append(mk(h, p, "Low", "Medium", "Potentially risky HTTP methods advertised", o, f"Methods listed: {m.group(1)}. Advertised via OPTIONS; not proof of exploitable behaviour.", "TRACE/PUT/DELETE may be unneeded.", "Depends on application handling.", "Disable unneeded methods.", "Test only with explicit approval."))
                if i == "http-headers":
                    low = o.lower(); miss = [n for n, k in (("Content-Security-Policy", "content-security-policy"), ("X-Content-Type-Options", "x-content-type-options"), ("X-Frame-Options/frame-ancestors", "x-frame-options")) if k not in low]
                    if "ssl" in (p["tunnel"] or "") and "strict-transport-security" not in low: miss.append("Strict-Transport-Security")
                    if miss: out.append(mk(h, p, "Low", "Medium", "Security headers absent on root response", o, f"Not seen on '/': {', '.join(miss)}.", "Relevance depends on application type; only the root response was inspected.", "Hardening gap, not a vulnerability by itself.", "Add headers appropriate to the application.", "Review a full browser response with devtools.", ["https://owasp.org/www-project-secure-headers/"]))
                if i == "ftp-anon" and "Anonymous FTP login allowed" in o:
                    out.append(mk(h, p, "Medium", "High", "Anonymous FTP login allowed", o, "Anonymous login succeeded (no files were read or written).", "Anonymous access may expose data and allow uploads.", "Data exposure or malware staging.", "Disable anonymous access or restrict to a read-only public dir.", "Review permissions manually."))
            if p["port"] in EXPOSED and not any(f["port"] == p["port"] and f["host"] == h["address"] and f["kind"] == "exposure" for f in out):
                n, sev = EXPOSED[p["port"]]
                out.append(mk(h, p, sev, "Low", f"{n} reachable from the scan source", f"{p['port']}/{p['proto']} open ({p['service']} {p['product']} {p['version']})".strip(), f"{n} is reachable. An open port alone does not show missing authentication or exploitability.",
                  "Administrative/data services are high-value if exposed beyond need.", "Depends on authentication and patch state.", "Restrict by firewall/VPN, require authentication and TLS, patch.", "Verify access controls from an authorized test host.", kind="exposure", app="Exposure only; requires validation."))
    return out
def risk(cve, conf):
    cv = (cve.get("cvss") or {}).get("score") or 0; ep = cve.get("epss") or 0; kev = bool(cve.get("kev"))
    s = 0.45 * cv / 10 + 0.2 * ep + (0.25 if kev else 0) + (0.1 if cve.get("exploit_refs") else 0)
    f = {"High": 1.0, "Medium": 0.7, "Low": 0.4}.get(conf, 0.4); s *= f
    sev = "Critical" if s >= .6 else "High" if s >= .4 else "Medium" if s >= .22 else "Low" if s >= .1 else "Informational"
    why = [f"CVSS {cv} (x0.45 weight)", f"EPSS {ep:.3f} (x0.2)", "CISA KEV listed (+0.25)" if kev else "not in CISA KEV", f"match confidence {conf} scales score x{f}", "unvalidated: technical severity and confidence are reported separately"]
    return {"score": round(s, 3), "severity": sev, "reasons": why}
