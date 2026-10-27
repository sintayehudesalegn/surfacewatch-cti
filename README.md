# SurfaceWatch CTI

Local Nmap assessment workbench by **Sintayehu Desalegn**: enter an asset, scan it, and get
evidence-based findings, CVE candidates with match rationale, KEV/EPSS context and downloadable reports.

> **Authorized use only.** Scan only assets you own or have written permission to test.

## Install and run (Debian/Ubuntu)

```bash
git clone https://github.com/sintayehudesalegn/surfacewatch-cti.git
cd surfacewatch-cti
sudo apt install -y nmap python3-venv
./run.sh                 # http://127.0.0.1:8000
sudo ./run.sh            # optional: SYN scans, UDP scans, OS detection
```

Check it: `curl -s http://127.0.0.1:8000/api/v1/health` and `python3 -m unittest tests.test_core`.
Optional: copy `.env.example` to `.env` and set `NVD_API_KEY` for much faster CVE lookups.

## Use

1. **Scan Manager**: type the asset (IP, hostname or CIDR), pick a profile, tick the authorization box, start.
2. **Results**: services, findings, CVE candidates and enrichment status. Click any row for details.
   Sort and filter every table. Export TXT, HTML, JSON or PDF, or download the raw Nmap XML.

Profiles: `quick` (top 100 TCP), `standard` (top 1000 TCP plus configuration checks),
`full` (all TCP ports), `udp` (top 30 UDP ports, needs root).

## How it stays safe

- The authorization box is required for every scan, and each authorized asset is recorded in the audit log.
- Link-local, cloud-metadata, multicast and reserved addresses are always blocked; ranges are capped (256 addresses).
- Hostnames are re-resolved at execution time and Nmap receives the resolved IPs.
- Nmap runs from fixed templates with an allowlist of non-intrusive scripts. No exploit, brute-force or `vuln` scripts.
- CVEs are candidates ("Potential version match" / "Requires validation"), never auto-confirmed. Distro-built
  packages are flagged for backport checks, and "no CVEs returned" is reported as a limitation, not as safety.
- The server binds to 127.0.0.1 and rejects foreign Host/Origin headers. There is no login, so do not expose it remotely.
- Enrichment sends product and version strings to NVD, CISA and FIRST; untick it per scan to avoid that.

Scan data lives in a local SQLite file (`surfacewatch.db`, git-ignored).

## Not implemented

PostgreSQL, Docker Compose, multi-user auth, MISP, ATT&CK mapping, distro security-tracker adapters,
local AI assistant, scheduled scans.

## License

MIT, Copyright (c) 2026 Sintayehu Desalegn Hadero.
