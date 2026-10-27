#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
command -v nmap >/dev/null || { echo "Install nmap first: sudo apt install -y nmap"; exit 1; }
[ -d .venv ] || python3 -m venv .venv
. .venv/bin/activate
pip install -q -r requirements.txt
[ -f .env ] && set -a && . ./.env && set +a
# sudo ./run.sh enables SYN/UDP scans and OS detection (venv python path preserved)
exec python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
