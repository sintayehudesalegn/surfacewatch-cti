import sqlite3, threading, os
from datetime import datetime, timezone
DB = os.environ.get("SW_DB", "surfacewatch.db")
_l = threading.Lock()
SCHEMA = [
 "create table if not exists scopes(id integer primary key autoincrement, kind text, value text unique, note text)",
 "create table if not exists scans(id text primary key, target text, profile text, status text, created text, finished text, config text, stages text, error text, raw_xml text, result text, operator text)",
 "create table if not exists cache(k text primary key, v text, ts real)",
 "create table if not exists state(key text primary key, status text, owner text, notes text, updated text)",
 "create table if not exists audit(ts text, actor text, action text, detail text)",
 "create table if not exists settings(k text primary key, v text)",
]
def q(sql, a=(), one=False):
    with _l:
        c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
        try:
            rows = [dict(r) for r in c.execute(sql, a).fetchall()]; c.commit()
            return (rows[0] if rows else None) if one else rows
        finally: c.close()
def init():
    for s in SCHEMA: q(s)
def now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")
def audit(action, detail="", actor="local-operator"): q("insert into audit values(?,?,?,?)", (now(), actor, action, detail))
