"""
Thin client for the ChaosKey encryption service, used by /proxy/* routes
so the browser never sees the user's ChaosKey API key.

Keeps one keep-alive http.client connection per worker thread (Flask's
dev/threaded server uses a thread per request) to avoid paying a fresh
TLS handshake (~40-80ms) on every encrypt/decrypt call.
"""
import http.client
import json as _json
import threading
import urllib.parse as _up

from config import CHAOSKEY_URL

_ck_parsed = _up.urlparse(CHAOSKEY_URL)
_CK_HOST   = _ck_parsed.netloc
_CK_HTTPS  = _ck_parsed.scheme == "https"

_ck_pool: dict[int, http.client.HTTPConnection] = {}  # thread id -> connection


def _ck_conn() -> http.client.HTTPConnection:
    tid = threading.get_ident()
    conn = _ck_pool.get(tid)
    if conn is None:
        conn = (
            http.client.HTTPSConnection(_CK_HOST, timeout=10)
            if _CK_HTTPS
            else http.client.HTTPConnection(_CK_HOST, timeout=10)
        )
        _ck_pool[tid] = conn
    return conn


def chaoskey_post(path: str, payload: dict, ck_key: str):
    """POST JSON to the ChaosKey API using the caller's per-account API key.

    Retries once on a stale keep-alive connection (RemoteDisconnected /
    BrokenPipeError / ConnectionResetError), which is the normal failure
    mode for a connection the server side has quietly closed.
    """
    body = _json.dumps(payload).encode()
    headers = {
        "Authorization":  f"Bearer {ck_key}",
        "Content-Type":   "application/json",
        "Content-Length": str(len(body)),
        "Connection":     "keep-alive",
    }
    for attempt in range(2):
        conn = _ck_conn()
        try:
            conn.request("POST", path, body=body, headers=headers)
            resp = conn.getresponse()
            data = _json.loads(resp.read())
            return data, resp.status
        except (http.client.RemoteDisconnected, BrokenPipeError, ConnectionResetError):
            conn.close()
            _ck_pool.pop(threading.get_ident(), None)
            if attempt == 1:
                raise
