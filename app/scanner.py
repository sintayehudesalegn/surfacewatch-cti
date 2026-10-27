"""Fixed nmap templates, safe subprocess execution, XML parsing."""
import os, shutil, subprocess, xml.etree.ElementTree as ET
SCRIPT_ALLOW = {  # id -> impact. No intrusive/exploit/brute scripts are allowlisted.
 "ssl-cert": "safe", "ssl-enum-ciphers": "low (many TLS handshakes)", "ssl-dh-params": "low", "ssl-date": "safe",
 "ssh2-enum-algos": "safe", "ssh-hostkey": "safe", "http-headers": "safe", "http-methods": "safe", "http-title": "safe",
 "smb-protocols": "safe", "smb2-security-mode": "safe", "smb-security-mode": "safe", "smtp-commands": "safe",
 "ftp-anon": "low (anonymous login attempt only; no file access)", "dns-nsid": "safe"}
CFG = ["ssl-cert", "ssl-enum-ciphers", "ssh2-enum-algos", "ssh-hostkey", "http-headers", "http-methods", "http-title",
       "smb-protocols", "smb2-security-mode", "smb-security-mode", "smtp-commands", "ftp-anon", "dns-nsid"]
PROFILES = {
 "quick": {"label": "Quick: top 100 TCP, light version detection, no scripts", "args": ["--top-ports", "100", "-sV", "--version-intensity", "2"], "scripts": []},
 "standard": {"label": "Standard: top 1000 TCP, version detection, allowlisted config checks", "args": ["--top-ports", "1000", "-sV", "--version-intensity", "5"], "scripts": CFG},
 "full": {"label": "Full TCP: all 65535 ports, version detection, allowlisted checks", "args": ["-p-", "-sV", "--version-intensity", "5"], "scripts": CFG},
 "udp": {"label": "UDP: top 30 ports (open|filtered is inconclusive; needs root)", "args": ["-sU", "--top-ports", "30", "-sV", "--version-intensity", "0"], "scripts": ["dns-nsid"]},
}
def nmap_path(): return shutil.which("nmap")
def build_cmd(profile, targets, skip_discovery=False, os_detect=False, timing=3, max_rate=0, host_timeout=1800):
    if profile not in PROFILES: raise ValueError("Unknown profile")
    root = hasattr(os, "geteuid") and os.geteuid() == 0
    if profile == "udp" and not root: raise ValueError("UDP scan requires root (run: sudo ./run.sh)")
    if os_detect and not root: raise ValueError("OS detection requires root")
    cmd = [nmap_path() or "nmap", "-oX", "-", "--no-stylesheet", "-n", f"-T{min(max(int(timing),1),4)}",
           "--host-timeout", f"{min(max(int(host_timeout),60),7200)}s", "--max-retries", "2"]
    if profile != "udp": cmd.append("-sS" if root else "-sT")
    cmd += PROFILES[profile]["args"]
    if skip_discovery: cmd.append("-Pn")
    if os_detect: cmd.append("-O")
    if max_rate: cmd += ["--max-rate", str(min(max(int(max_rate), 1), 2000))]
    sc = [s for s in PROFILES[profile]["scripts"] if s in SCRIPT_ALLOW]
    if sc: cmd += ["--script", ",".join(sc)]
    return cmd + ["--"] + list(targets)  # argv list; never a shell
def run(cmd, timeout, holder):
    pr = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=False)
    holder["proc"] = pr
    try: out, err = pr.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        pr.kill(); pr.communicate(); raise TimeoutError("Scan exceeded the time limit")
    if holder.get("cancel"): raise InterruptedError("Cancelled")
    return out, err, pr.returncode
def parse(xml_text):
    try: root = ET.fromstring(xml_text)
    except ET.ParseError as e: raise ValueError(f"Invalid Nmap XML: {e}")
    warns = [] if root.find("runstats/finished") is not None else ["Nmap XML lacks a 'finished' element; output may be incomplete"]
    hosts = []
    for h in root.findall("host"):
        st = h.find("status"); ad = [a.get("addr") for a in h.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")]
        host = {"address": ad[0] if ad else "?", "state": st.get("state") if st is not None else "?",
                "hostnames": [x.get("name") for x in h.findall("hostnames/hostname")],
                "os": [{"name": m.get("name"), "accuracy": m.get("accuracy")} for m in h.findall("os/osmatch")[:3]], "ports": []}
        for p in h.findall("ports/port"):
            s = p.find("state"); sv = p.find("service")
            port = {"port": int(p.get("portid")), "proto": p.get("protocol"), "state": s.get("state") if s is not None else "?",
                    "reason": s.get("reason", "") if s is not None else "", "service": "", "product": "", "version": "", "extrainfo": "",
                    "method": "", "conf": "", "tunnel": "", "cpes": [], "scripts": []}
            if sv is not None:
                port.update(service=sv.get("name", ""), product=sv.get("product", ""), version=sv.get("version", ""), extrainfo=sv.get("extrainfo", ""),
                            method=sv.get("method", ""), conf=sv.get("conf", ""), tunnel=sv.get("tunnel", ""), cpes=[c.text for c in sv.findall("cpe") if c.text])
            port["scripts"] = [{"id": sc.get("id"), "output": sc.get("output", ""), "completed": True} for sc in p.findall("script")]
            host["ports"].append(port)
        hosts.append(host)
    return {"hosts": hosts, "warnings": warns}
