import base64
import hashlib
import hmac
import secrets
import threading
import time


def hash_password(password):
    if not isinstance(password, str) or not 12 <= len(password) <= 128:
        raise ValueError("Use a password between 12 and 128 characters")
    salt = secrets.token_bytes(16)
    result = hashlib.scrypt(password.encode(), salt=salt, n=32768, r=8, p=1, maxmem=64 * 1024 * 1024)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(result).decode()


def check_password(password, encoded):
    try:
        if not isinstance(password, str) or len(password) > 128:
            return False
        scheme, salt, expected = encoded.split("$")
        if scheme != "scrypt":
            return False
        actual = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=32768, r=8, p=1, maxmem=64 * 1024 * 1024)
        return hmac.compare_digest(actual, base64.b64decode(expected))
    except (ValueError, TypeError):
        return False


class LoginLimiter:
    """Per-address login throttling. Gunicorn must use one shared database limiter."""
    def __init__(self, store):
        self.store = store
        with store.db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS login_attempts (address TEXT NOT NULL, ts REAL NOT NULL)")

    def allow(self, address):
        now = time.time()
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM login_attempts WHERE ts<?", (now - 900,))
            count = db.execute("SELECT count(*) FROM login_attempts WHERE address=?", (address,)).fetchone()[0]
            if count >= 10:
                return False
            db.execute("INSERT INTO login_attempts VALUES (?,?)", (address, now))
        return True

    def clear(self, address):
        with self.store.db() as db:
            db.execute("DELETE FROM login_attempts WHERE address=?", (address,))
