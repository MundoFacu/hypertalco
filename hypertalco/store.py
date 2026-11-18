"""Local SQLite state; a fresh connection per operation, no shared cursors."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
import uuid


class Store:
    def __init__(self, folder):
        self.folder = Path(folder)
        self.folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = self.folder / "hypertalco.sqlite3"
        with self.db() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY, password TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, username TEXT NOT NULL,
                    csrf TEXT NOT NULL, expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, operation TEXT NOT NULL,
                    payload TEXT NOT NULL, actor TEXT NOT NULL, status TEXT NOT NULL,
                    created REAL NOT NULL, started REAL, finished REAL, result TEXT, error TEXT);
                CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, ts REAL NOT NULL,
                    actor TEXT NOT NULL, event TEXT NOT NULL, detail TEXT NOT NULL);
            """)
        self.path.chmod(0o600)

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def user(self, name):
        with self.db() as db:
            row = db.execute("SELECT password FROM users WHERE name=?", (name,)).fetchone()
            return row[0] if row else None

    def set_user(self, name, password_hash, reset=False):
        with self.db() as db:
            if db.execute("SELECT count(*) FROM users").fetchone()[0] and not reset:
                raise ValueError("An administrator already exists; use reset-password")
            db.execute("INSERT INTO users VALUES (?,?) ON CONFLICT(name) DO UPDATE SET password=excluded.password", (name, password_hash))
            db.execute("DELETE FROM sessions")

    def new_session(self, username):
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self.db() as db:
            db.execute("DELETE FROM sessions WHERE expires<?", (time.time(),))
            db.execute("INSERT INTO sessions VALUES (?,?,?,?)", (hashlib.sha256(token.encode()).hexdigest(), username, csrf, time.time() + 8 * 3600))
        return token, csrf

    def session(self, token):
        if not token or len(token) > 100:
            return None
        with self.db() as db:
            row = db.execute("SELECT username,csrf FROM sessions WHERE token=? AND expires>?", (hashlib.sha256(token.encode()).hexdigest(), time.time())).fetchone()
            return dict(row) if row else None

    def logout(self, token):
        with self.db() as db:
            db.execute("DELETE FROM sessions WHERE token=?", (hashlib.sha256(token.encode()).hexdigest(),))

    def audit(self, actor, event, detail=""):
        with self.db() as db:
            db.execute("INSERT INTO audit(ts,actor,event,detail) VALUES (?,?,?,?)", (time.time(), actor, event, detail[:500]))

    def audit_rows(self):
        with self.db() as db:
            return [dict(r) for r in db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 100")]

    def enqueue(self, operation, payload, actor):
        job_id = str(uuid.uuid4())
        with self.db() as db:
            if db.execute("SELECT count(*) FROM jobs WHERE status IN ('queued','running')").fetchone()[0] >= 100:
                raise ValueError("The job queue is full")
            db.execute("INSERT INTO jobs(id,operation,payload,actor,status,created) VALUES (?,?,?,?,?,?)", (job_id, operation, json.dumps(payload), actor, "queued", time.time()))
            db.execute("INSERT INTO audit(ts,actor,event,detail) VALUES (?,?,?,?)", (time.time(), actor, "job.queued", operation + " " + job_id))
        return job_id

    def jobs(self):
        with self.db() as db:
            # The queue payload can contain container environment secrets; never return it.
            return [dict(r) for r in db.execute("SELECT id,operation,actor,status,created,started,finished,result,error FROM jobs ORDER BY created DESC LIMIT 100")]

    def claim(self):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM jobs WHERE status='queued' ORDER BY created LIMIT 1").fetchone()
            if not row:
                return None
            db.execute("UPDATE jobs SET status='running',started=? WHERE id=?", (time.time(), row["id"]))
            return {**dict(row), "payload": json.loads(row["payload"])}

    def finish(self, job_id, result=None, error=None):
        with self.db() as db:
            db.execute("UPDATE jobs SET status=?,finished=?,result=?,error=?,payload='{}' WHERE id=?", ("failed" if error else "succeeded", time.time(), json.dumps(result) if result else None, error, job_id))

    def recover_jobs(self):
        with self.db() as db:
            db.execute("UPDATE jobs SET status='interrupted',payload='{}',finished=?,error='Worker restarted. Check inventory before retrying.' WHERE status='running'", (time.time(),))
