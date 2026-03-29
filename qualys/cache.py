"""SQLite-backed L2 disk cache with per-type TTLs."""

import os
import pickle
import sqlite3
import threading
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Cache directory & DB path
# ---------------------------------------------------------------------------

CACHE_DIR = Path(os.environ.get("QUALYS_MCP_CACHE_DIR", Path.home() / ".cache" / "qualys-mcp"))
DB_PATH = CACHE_DIR / "cache.db"

# ---------------------------------------------------------------------------
# Per-type TTL constants (seconds), each overridable via env var
# ---------------------------------------------------------------------------

TTL_VMDR = int(os.environ.get("CACHE_TTL_VMDR", 4 * 3600))
TTL_CSAM = int(os.environ.get("CACHE_TTL_CSAM", 6 * 3600))
TTL_CERTS = int(os.environ.get("CACHE_TTL_CERTS", 12 * 3600))
TTL_CLOUD = int(os.environ.get("CACHE_TTL_CLOUD", 6 * 3600))
TTL_PATCH = int(os.environ.get("CACHE_TTL_PATCH", 1 * 3600))
TTL_COMPLIANCE = int(os.environ.get("CACHE_TTL_COMPLIANCE", 1 * 3600))
TTL_SCANNERS = int(os.environ.get("CACHE_TTL_SCANNERS", 12 * 3600))
TTL_WAS = int(os.environ.get("CACHE_TTL_WAS", 4 * 3600))
TTL_ETM = int(os.environ.get("CACHE_TTL_ETM", 2 * 3600))
TTL_CONTAINERS = int(os.environ.get("CACHE_TTL_CONTAINERS", 6 * 3600))
TTL_DEFAULT = int(os.environ.get("CACHE_TTL_DEFAULT", 4 * 3600))


# ---------------------------------------------------------------------------
# DiskCache
# ---------------------------------------------------------------------------

class DiskCache:
    """Thread-safe SQLite-backed cache. All errors are caught and logged."""

    def __init__(self):
        self._lock = threading.Lock()
        self._conn = None
        try:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS cache "
                "(key TEXT PRIMARY KEY, value BLOB, fetched_at REAL, ttl INTEGER)"
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            import sys
            print(f"[qualys-mcp] DiskCache init warning: {exc}", file=sys.stderr)

    def get(self, key):
        """Return unpickled value if not expired, else None."""
        with self._lock:
            try:
                if self._conn is None:
                    return None
                row = self._conn.execute(
                    "SELECT value, fetched_at, ttl FROM cache WHERE key = ?", (key,)
                ).fetchone()
                if row is None:
                    return None
                value_blob, fetched_at, ttl = row
                if time.time() - fetched_at > ttl:
                    return None
                return pickle.loads(value_blob)
            except Exception as exc:
                import sys
                print(f"[qualys-mcp] DiskCache.get warning: {exc}", file=sys.stderr)
                return None

    def set(self, key, value, ttl):
        """Pickle value and upsert into cache."""
        with self._lock:
            try:
                if self._conn is None:
                    return
                blob = pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL)
                self._conn.execute(
                    "INSERT OR REPLACE INTO cache (key, value, fetched_at, ttl) VALUES (?, ?, ?, ?)",
                    (key, blob, time.time(), ttl),
                )
                self._conn.commit()
            except Exception as exc:
                import sys
                print(f"[qualys-mcp] DiskCache.set warning: {exc}", file=sys.stderr)

    def clear(self, key=None):
        """Delete specific key or all rows."""
        with self._lock:
            try:
                if self._conn is None:
                    return
                if key:
                    self._conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                else:
                    self._conn.execute("DELETE FROM cache")
                self._conn.commit()
            except Exception as exc:
                import sys
                print(f"[qualys-mcp] DiskCache.clear warning: {exc}", file=sys.stderr)

    def age(self, key):
        """Seconds since fetched_at, or None if missing/expired."""
        with self._lock:
            try:
                if self._conn is None:
                    return None
                row = self._conn.execute(
                    "SELECT fetched_at, ttl FROM cache WHERE key = ?", (key,)
                ).fetchone()
                if row is None:
                    return None
                fetched_at, ttl = row
                elapsed = time.time() - fetched_at
                if elapsed > ttl:
                    return None
                return int(elapsed)
            except Exception as exc:
                import sys
                print(f"[qualys-mcp] DiskCache.age warning: {exc}", file=sys.stderr)
                return None

    def size_kb(self):
        """Return DB file size in KB, or 0."""
        try:
            return int(DB_PATH.stat().st_size / 1024) if DB_PATH.exists() else 0
        except OSError:
            return 0

    def keys(self):
        """Return list of non-expired cache keys."""
        with self._lock:
            try:
                if self._conn is None:
                    return []
                now = time.time()
                rows = self._conn.execute(
                    "SELECT key FROM cache WHERE (? - fetched_at) <= ttl", (now,)
                ).fetchall()
                return [r[0] for r in rows]
            except Exception:
                return []


# Module-level singleton
disk_cache = DiskCache()
