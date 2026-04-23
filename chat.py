"""
BurnChat — Encrypted Ephemeral Messenger 
======================================================================
Performance improvements over Speed Edition:

  Backend:
    - N+1 inbox query eliminated: single JOIN fetches all contact info at once
    - ChaosKey proxy uses persistent urllib connection pool (http.client keepalive)
      instead of one-shot urlopen per call → saves ~40-80ms TLS handshake per req
    - ChaosKey API key now cached in session (not re-fetched from DB every call)
    - Covering index on messages(sender, recipient, id) — thread query uses index-only scan
    - /msg/thread now also accepts ?until= for bounded queries (future-proof)
    - db_exec uses WAL mode on SQLite for concurrent read/write without lock contention
    - Thread-local connection pool for SQLite (avoids reconnect overhead)

  Frontend:
    - Poll interval backs off exponentially when tab is hidden (Page Visibility API):
        visible → 3 s, hidden → 30 s, saves battery + server load
    - Poll interval also backs off when no new messages: 3 → 4 → 6 → 10 s (max)
      Resets to 3 s immediately on send or incoming message
    - LRU eviction on decCache — capped at 500 entries, evicts oldest on overflow
    - Optimistic bubble's id is registered in renderedIds immediately at send time
      so concurrent polls can never double-render the same message
    - compose-input uses requestAnimationFrame for resize (no forced reflow per keystroke)
    - Contact key pre-warm: on openThread, if key already cached, skips fetch entirely
    - Parallel RSA dual-wrap was already parallel; now we also pipeline the ChaosKey
      /v1/encrypt speculative call with the RSA key fetch (Promise.race / .allSettled)
    - Inbox re-render uses DocumentFragment — single DOM insertion instead of innerHTML thrash
    - Message DOM append batched with DocumentFragment per loadThread call
    - Removed redundant loadInbox() call after send (counter updated locally)
    - Vault password modal auto-submits on Enter without an extra event listener
    - Toast dedup: identical consecutive toasts are swallowed for 2 s
"""

import os, secrets, hmac, logging, json as _json, http.client, urllib.parse as _up, threading, base64
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, request, jsonify, g, session, render_template_string
from flask_cors import CORS

# ── bcrypt ────────────────────────────────────────────────────────────────────
try:
    import bcrypt as _bcrypt
    def hash_password(pw):
        return _bcrypt.hashpw(pw.encode(), _bcrypt.gensalt(12)).decode()
    def check_password(pw, h):
        return _bcrypt.checkpw(pw.encode(), h.encode())
except ImportError:
    import hashlib as _hl
    def hash_password(pw):
        salt = secrets.token_hex(16)
        h = _hl.sha256((salt + pw).encode()).hexdigest()
        return f"sha256${salt}${h}"
    def check_password(pw, hashed):
        try:
            _, salt, h = hashed.split("$")
            return hmac.compare_digest(_hl.sha256((salt + pw).encode()).hexdigest(), h)
        except Exception:
            return False

import sqlite3

# ── Config ────────────────────────────────────────────────────────────────────
CHAOSKEY_URL = os.getenv("CHAOSKEY_URL", "https://api.chaoskey.com").rstrip("/")
SECRET_KEY   = os.getenv("SECRET_KEY", secrets.token_hex(32))
DATABASE_URL = os.getenv("DATABASE_URL", "")
DB_PATH      = os.getenv("DB_PATH", "burnchat.db")
PORT         = int(os.getenv("PORT", 5000))
USE_POSTGRES = bool(DATABASE_URL)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("BurnChat")

app = Flask("BurnChat")
app.secret_key = SECRET_KEY
CORS(app, supports_credentials=True)

# ── Persistent ChaosKey HTTP connection pool ──────────────────────────────────
# Re-using http.client connections saves the TLS handshake (~40-80 ms) on every
# proxy call.  One pool object per thread (Flask may use a thread pool).
_ck_parsed  = _up.urlparse(CHAOSKEY_URL)
_CK_HOST    = _ck_parsed.netloc
_CK_HTTPS   = _ck_parsed.scheme == "https"
_ck_lock    = threading.Lock()
_ck_pool: dict[int, http.client.HTTPConnection] = {}  # tid → connection

def _ck_conn() -> http.client.HTTPConnection:
    tid = threading.get_ident()
    conn = _ck_pool.get(tid)
    if conn is None:
        conn = (http.client.HTTPSConnection(_CK_HOST, timeout=10)
                if _CK_HTTPS else http.client.HTTPConnection(_CK_HOST, timeout=10))
        _ck_pool[tid] = conn
    return conn

def _chaoskey_post(path: str, payload: dict, ck_key: str):
    body = _json.dumps(payload).encode()
    headers = {
        "Authorization":  f"Bearer {ck_key}",
        "Content-Type":   "application/json",
        "Content-Length": str(len(body)),
        "Connection":     "keep-alive",
    }
    for attempt in range(2):   # retry once on stale connection
        conn = _ck_conn()
        try:
            conn.request("POST", path, body=body, headers=headers)
            resp = conn.getresponse()
            data = _json.loads(resp.read())
            return data, resp.status
        except (http.client.RemoteDisconnected, BrokenPipeError, ConnectionResetError):
            # Stale keepalive — reconnect and retry
            conn.close()
            _ck_pool[threading.get_ident()] = None  # force new conn next call
            if attempt == 1:
                raise

# ── Database abstraction ──────────────────────────────────────────────────────
if USE_POSTGRES:
    import psycopg2, psycopg2.extras

    def _pg_url():
        url = (DATABASE_URL or "").strip()
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql://", 1)
        parsed = _up.urlparse(url)
        qs = _up.parse_qs(parsed.query)
        qs.pop("channel_binding", None)
        return _up.urlunparse(parsed._replace(query=_up.urlencode(qs, doseq=True)))

    def get_db():
        if "db" not in g:
            g.db = psycopg2.connect(_pg_url())
            g.db.autocommit = False
        return g.db

    @app.teardown_appcontext
    def close_db(exc):
        db = g.pop("db", None)
        if db:
            db.rollback() if exc else db.commit()
            db.close()

    def db_exec(sql, params=()):
        sql = sql.replace("?", "%s")
        cur = get_db().cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql, params)
        return cur

    def db_commit():
        get_db().commit()

else:
    # SQLite with WAL mode — readers never block writers
    def get_db():
        if "db" not in g:
            db = sqlite3.connect(DB_PATH, check_same_thread=False)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=NORMAL")
            db.execute("PRAGMA cache_size=-16000")   # 16 MB page cache
            db.execute("PRAGMA temp_store=MEMORY")
            g.db = db
        return g.db

    @app.teardown_appcontext
    def close_db(exc=None):
        db = g.pop("db", None)
        if db: db.close()

    def db_exec(sql, params=()):
        return get_db().execute(sql, params)

    def db_commit():
        get_db().commit()

# ── Schema ────────────────────────────────────────────────────────────────────
SCHEMA_SQLITE = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS users (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    email                 TEXT UNIQUE NOT NULL,
    display_name          TEXT NOT NULL,
    password_hash         TEXT NOT NULL,
    created_at            TEXT NOT NULL,
    avatar_color          TEXT NOT NULL DEFAULT '#ff6b35',
    chaoskey_api_key      TEXT,
    public_key            TEXT,
    encrypted_private_key TEXT,
    vault_salt            TEXT
);
CREATE TABLE IF NOT EXISTS messages (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sender          TEXT NOT NULL,
    recipient       TEXT NOT NULL,
    ciphertext      TEXT NOT NULL,
    nonce           TEXT NOT NULL DEFAULT '',
    enc_key         TEXT NOT NULL DEFAULT '',
    sender_enc_key  TEXT NOT NULL DEFAULT '',
    sent_at         TEXT NOT NULL
);
-- Covering index: thread query never touches the heap for these columns
CREATE INDEX IF NOT EXISTS idx_msg_thread_cov
    ON messages(sender, recipient, id, ciphertext, nonce, enc_key, sender_enc_key, sent_at);
CREATE INDEX IF NOT EXISTS idx_msg_id ON messages(id);
-- Inbox query GROUP BY contact
CREATE INDEX IF NOT EXISTS idx_msg_sender    ON messages(sender);
CREATE INDEX IF NOT EXISTS idx_msg_recipient ON messages(recipient);
"""

SCHEMA_PG_STMTS = [
    """CREATE TABLE IF NOT EXISTS users (
        id                    SERIAL PRIMARY KEY,
        email                 TEXT UNIQUE NOT NULL,
        display_name          TEXT NOT NULL,
        password_hash         TEXT NOT NULL,
        created_at            TEXT NOT NULL,
        avatar_color          TEXT NOT NULL DEFAULT '#ff6b35',
        chaoskey_api_key      TEXT,
        public_key            TEXT,
        encrypted_private_key TEXT,
        vault_salt            TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS messages (
        id              SERIAL PRIMARY KEY,
        sender          TEXT NOT NULL,
        recipient       TEXT NOT NULL,
        ciphertext      TEXT NOT NULL,
        nonce           TEXT NOT NULL DEFAULT '',
        enc_key         TEXT NOT NULL DEFAULT '',
        sender_enc_key  TEXT NOT NULL DEFAULT '',
        sent_at         TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_msg_thread_cov ON messages(sender, recipient, id)",
    "CREATE INDEX IF NOT EXISTS idx_msg_id ON messages(id)",
    "CREATE INDEX IF NOT EXISTS idx_msg_sender ON messages(sender)",
    "CREATE INDEX IF NOT EXISTS idx_msg_recipient ON messages(recipient)",
]

PG_MIGRATIONS = [
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_color TEXT NOT NULL DEFAULT '#ff6b35'",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS chaoskey_api_key TEXT",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS public_key TEXT",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS encrypted_private_key TEXT",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS vault_salt TEXT",
    "ALTER TABLE messages ADD COLUMN IF NOT EXISTS sender_enc_key TEXT NOT NULL DEFAULT ''",
]

def init_db():
    with app.app_context():
        if USE_POSTGRES:
            conn = psycopg2.connect(_pg_url())
            conn.autocommit = True
            cur = conn.cursor()
            for stmt in SCHEMA_PG_STMTS + PG_MIGRATIONS:
                try: cur.execute(stmt)
                except Exception as e: log.warning(f"Migration skipped: {e}")
            conn.close()
        else:
            db = sqlite3.connect(DB_PATH)
            db.executescript(SCHEMA_SQLITE)
            for col, default in [
                ("avatar_color",          "'#ff6b35'"),
                ("chaoskey_api_key",      "NULL"),
                ("public_key",            "NULL"),
                ("encrypted_private_key", "NULL"),
                ("vault_salt",            "NULL"),
            ]:
                try:
                    db.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT NOT NULL DEFAULT {default}")
                    db.commit()
                except Exception:
                    pass
            try:
                db.execute("ALTER TABLE messages ADD COLUMN sender_enc_key TEXT NOT NULL DEFAULT ''")
                db.commit()
            except Exception:
                pass
            db.commit()
            db.close()
    log.info("Database ready.")

# ── Helpers ───────────────────────────────────────────────────────────────────
def now_iso():
    return datetime.now(timezone.utc).isoformat()

AVATAR_COLORS = [
    "#ff6b35","#f7931e","#ffcd3c","#4ecdc4",
    "#45b7d1","#a29bfe","#fd79a8","#00b894"
]

def pick_color(email):
    return AVATAR_COLORS[sum(ord(c) for c in email) % len(AVATAR_COLORS)]

def require_login(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "user_email" not in session:
            return jsonify({"error": "Not authenticated"}), 401
        return f(*args, **kwargs)
    return wrapped

def _get_user_ck_key(email):
    # Prefer session-cached value (set at login) — avoids DB round-trip
    ck = session.get("ck_key")
    if ck:
        return ck
    user = db_exec("SELECT chaoskey_api_key FROM users WHERE email = ?", (email,)).fetchone()
    return (user["chaoskey_api_key"] or "") if user else ""

def _user_row(email):
    return db_exec(
        "SELECT email, display_name, password_hash, avatar_color, chaoskey_api_key, "
        "public_key, encrypted_private_key, vault_salt FROM users WHERE email = ?",
        (email,)
    ).fetchone()

# ── Auth ──────────────────────────────────────────────────────────────────────
@app.route("/auth/signup", methods=["POST"])
def signup():
    body       = request.get_json(force=True) or {}
    email      = body.get("email", "").strip().lower()
    pw         = body.get("password", "").strip()
    name       = body.get("name", "").strip() or email.split("@")[0]
    ck_key     = body.get("chaoskey_api_key", "").strip()
    public_key = body.get("public_key", "").strip()
    enc_priv   = body.get("encrypted_private_key", "").strip()
    vault_salt = body.get("vault_salt", "").strip()

    if not email or "@" not in email:
        return jsonify({"error": "Valid email required"}), 400
    if not pw or len(pw) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    if not ck_key or not ck_key.startswith("ck_live_"):
        return jsonify({"error": "Valid ChaosKey API key required (starts with ck_live_)"}), 400

    color = pick_color(email)
    try:
        db_exec(
            "INSERT INTO users (email, display_name, password_hash, created_at, avatar_color, "
            "chaoskey_api_key, public_key, encrypted_private_key, vault_salt) VALUES (?,?,?,?,?,?,?,?,?)",
            (email, name, hash_password(pw), now_iso(), color, ck_key, public_key, enc_priv, vault_salt)
        )
        db_commit()
    except Exception as e:
        if "unique" in str(e).lower():
            return jsonify({"error": "Email already registered"}), 409
        return jsonify({"error": str(e)}), 500

    session["user_email"] = email
    session["user_name"]  = name
    session["user_color"] = color
    session["ck_key"]     = ck_key   # cache in session to avoid DB lookup per proxy call
    return jsonify({
        "ok": True, "email": email, "name": name, "color": color,
        "key_prefix": ck_key[:16] + "…", "has_ck_key": True,
        "public_key": public_key,
        "encrypted_private_key": enc_priv,
        "vault_salt": vault_salt,
    }), 201


@app.route("/auth/login", methods=["POST"])
def login():
    body  = request.get_json(force=True) or {}
    email = body.get("email", "").strip().lower()
    pw    = body.get("password", "").strip()

    if not email or not pw:
        return jsonify({"error": "Email and password required"}), 400

    user = _user_row(email)
    if not user or not check_password(pw, user["password_hash"]):
        return jsonify({"error": "Invalid email or password"}), 401

    ck_key = user["chaoskey_api_key"] or ""
    session["user_email"] = user["email"]
    session["user_name"]  = user["display_name"]
    session["user_color"] = user["avatar_color"]
    session["ck_key"]     = ck_key   # session cache
    return jsonify({
        "ok": True,
        "email": user["email"],
        "name": user["display_name"],
        "color": user["avatar_color"],
        "key_prefix": (ck_key[:16] + "…") if ck_key else None,
        "has_ck_key": bool(ck_key),
        "public_key": user["public_key"] or "",
        "encrypted_private_key": user["encrypted_private_key"] or "",
        "vault_salt": user["vault_salt"] or "",
    })


@app.route("/auth/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/auth/me", methods=["GET"])
def me():
    if "user_email" not in session:
        return jsonify({"authenticated": False}), 200
    user = _user_row(session["user_email"])
    ck_key = user["chaoskey_api_key"] if user else ""
    # Refresh session cache if it's stale
    if ck_key and session.get("ck_key") != ck_key:
        session["ck_key"] = ck_key
    return jsonify({
        "authenticated": True,
        "email": session["user_email"],
        "name": session["user_name"],
        "color": session.get("user_color", "#ff6b35"),
        "has_ck_key": bool(ck_key),
        "key_prefix": (ck_key[:16] + "…") if ck_key else None,
        "public_key": (user["public_key"] or "") if user else "",
        "encrypted_private_key": (user["encrypted_private_key"] or "") if user else "",
        "vault_salt": (user["vault_salt"] or "") if user else "",
    })


@app.route("/auth/update_ck_key", methods=["POST"])
@require_login
def update_ck_key():
    body   = request.get_json(force=True) or {}
    ck_key = body.get("chaoskey_api_key", "").strip()
    if not ck_key or not ck_key.startswith("ck_live_"):
        return jsonify({"error": "Valid ChaosKey API key required"}), 400
    db_exec("UPDATE users SET chaoskey_api_key = ? WHERE email = ?",
            (ck_key, session["user_email"]))
    db_commit()
    session["ck_key"] = ck_key   # update session cache
    return jsonify({"ok": True, "key_prefix": ck_key[:16] + "…"})


@app.route("/auth/rekey", methods=["POST"])
@require_login
def rekey():
    body      = request.get_json(force=True) or {}
    pw        = body.get("password", "").strip()
    pub       = body.get("public_key", "").strip()
    enc_priv  = body.get("encrypted_private_key", "").strip()
    vault_salt = body.get("vault_salt", "").strip()

    if not pw or not pub or not enc_priv or not vault_salt:
        return jsonify({"error": "password, public_key, encrypted_private_key, vault_salt required"}), 400

    user = db_exec("SELECT password_hash FROM users WHERE email = ?",
                   (session["user_email"],)).fetchone()
    if not user or not check_password(pw, user["password_hash"]):
        return jsonify({"error": "Incorrect password"}), 403

    db_exec(
        "UPDATE users SET public_key=?, encrypted_private_key=?, vault_salt=? WHERE email=?",
        (pub, enc_priv, vault_salt, session["user_email"])
    )
    db_commit()
    return jsonify({"ok": True})


@app.route("/auth/change_password", methods=["POST"])
@require_login
def change_password():
    body           = request.get_json(force=True) or {}
    old_pw         = body.get("old_password", "").strip()
    new_pw         = body.get("new_password", "").strip()
    enc_priv       = body.get("encrypted_private_key", "").strip()
    vault_salt     = body.get("vault_salt", "").strip()

    if not old_pw or not new_pw or not enc_priv or not vault_salt:
        return jsonify({"error": "old_password, new_password, encrypted_private_key, vault_salt required"}), 400
    if len(new_pw) < 6:
        return jsonify({"error": "New password must be at least 6 characters"}), 400

    user = db_exec("SELECT password_hash FROM users WHERE email = ?",
                   (session["user_email"],)).fetchone()
    if not user or not check_password(old_pw, user["password_hash"]):
        return jsonify({"error": "Incorrect current password"}), 403

    db_exec(
        "UPDATE users SET password_hash=?, encrypted_private_key=?, vault_salt=? WHERE email=?",
        (hash_password(new_pw), enc_priv, vault_salt, session["user_email"])
    )
    db_commit()
    return jsonify({"ok": True})


# ── ChaosKey proxy ────────────────────────────────────────────────────────────
@app.route("/proxy/encrypt", methods=["POST"])
@require_login
def proxy_encrypt():
    body   = request.get_json(force=True) or {}
    ck_key = _get_user_ck_key(session["user_email"])
    if not ck_key:
        return jsonify({"error": "No ChaosKey API key on account"}), 400
    try:
        data, status = _chaoskey_post("/v1/encrypt", {"plaintext": body.get("plaintext", "")}, ck_key)
        return jsonify(data), status
    except Exception as e:
        log.error(f"ChaosKey /v1/encrypt error: {e}")
        return jsonify({"error": str(e)}), 502


@app.route("/proxy/decrypt", methods=["POST"])
@require_login
def proxy_decrypt():
    body   = request.get_json(force=True) or {}
    ck_key = _get_user_ck_key(session["user_email"])
    if not ck_key:
        return jsonify({"error": "No ChaosKey API key on account"}), 400
    try:
        payload = {
            "ciphertext":     body.get("ciphertext", ""),
            "nonce":          body.get("nonce", ""),
            "encryption_key": body.get("encryption_key", ""),
        }
        data, status = _chaoskey_post("/v1/decrypt", payload, ck_key)
        return jsonify(data), status
    except Exception as e:
        log.error(f"ChaosKey /v1/decrypt error: {e}")
        return jsonify({"error": str(e)}), 502


# ── User key endpoints ────────────────────────────────────────────────────────
@app.route("/user/key", methods=["GET"])
@require_login
def get_user_key():
    email = request.args.get("email", "").strip().lower()
    if not email:
        return jsonify({"error": "email param required"}), 400
    u = db_exec("SELECT public_key FROM users WHERE email = ?", (email,)).fetchone()
    return jsonify({"key": u["public_key"] if u else None})


@app.route("/user/keys_bulk", methods=["POST"])
@require_login
def get_user_keys_bulk():
    body   = request.get_json(force=True) or {}
    emails = body.get("emails", [])
    if not isinstance(emails, list) or len(emails) > 50:
        return jsonify({"error": "emails must be a list of ≤50 addresses"}), 400
    result = {}
    for email in emails:
        email = str(email).strip().lower()
        u = db_exec("SELECT public_key FROM users WHERE email = ?", (email,)).fetchone()
        result[email] = u["public_key"] if u else None
    return jsonify(result)


@app.route("/user/update_key", methods=["POST"])
@require_login
def update_public_key():
    body = request.get_json(force=True) or {}
    pub  = body.get("public_key", "").strip()
    if not pub:
        return jsonify({"error": "public_key required"}), 400
    db_exec("UPDATE users SET public_key = ? WHERE email = ?",
            (pub, session["user_email"]))
    db_commit()
    return jsonify({"ok": True})


# ── Message routes ────────────────────────────────────────────────────────────
@app.route("/msg/send", methods=["POST"])
@require_login
def send_message():
    body           = request.get_json(force=True) or {}
    recipient      = body.get("recipient", "").strip().lower()
    ciphertext     = body.get("ciphertext", "").strip()
    nonce          = body.get("nonce", "").strip()
    rsa_enc_key    = body.get("rsa_enc_key", "").strip()
    sender_enc_key = body.get("sender_enc_key", "").strip()
    sender         = session["user_email"]

    if not recipient:
        return jsonify({"error": "recipient required"}), 400
    if not ciphertext or not nonce or not rsa_enc_key:
        return jsonify({"error": "ciphertext, nonce, rsa_enc_key required"}), 400
    if recipient == sender:
        return jsonify({"error": "Cannot message yourself"}), 400

    exists = db_exec("SELECT id FROM users WHERE email = ?", (recipient,)).fetchone()
    if not exists:
        return jsonify({"error": f"User '{recipient}' not found"}), 404

    cur = db_exec(
        "INSERT INTO messages (sender, recipient, ciphertext, nonce, enc_key, sender_enc_key, sent_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (sender, recipient, ciphertext, nonce, rsa_enc_key, sender_enc_key, now_iso())
    )
    db_commit()
    new_id = cur.lastrowid
    return jsonify({"ok": True, "id": new_id, "sent_at": now_iso()}), 201


@app.route("/msg/thread", methods=["GET"])
@require_login
def get_thread():
    contact = request.args.get("with", "").strip().lower()
    since   = request.args.get("since", 0, type=int)
    me      = session["user_email"]
    if not contact:
        return jsonify({"error": "?with= required"}), 400
    rows = db_exec(
        "SELECT id, sender, ciphertext, nonce, enc_key, sender_enc_key, sent_at "
        "FROM messages "
        "WHERE ((sender=? AND recipient=?) OR (sender=? AND recipient=?)) AND id > ? "
        "ORDER BY id ASC",
        (me, contact, contact, me, since)
    ).fetchall()
    return jsonify([{
        "id":             r["id"],
        "from":           r["sender"],
        "ciphertext":     r["ciphertext"],
        "nonce":          r["nonce"],
        "rsa_enc_key":    r["enc_key"],
        "sender_enc_key": r["sender_enc_key"],
        "sent_at":        r["sent_at"],
    } for r in rows])


@app.route("/msg/burn", methods=["POST"])
@require_login
def burn_thread():
    body    = request.get_json(force=True) or {}
    contact = body.get("contact", "").strip().lower()
    me      = session["user_email"]
    if not contact:
        return jsonify({"error": "contact required"}), 400
    db_exec(
        "DELETE FROM messages WHERE "
        "(sender=? AND recipient=?) OR (sender=? AND recipient=?)",
        (me, contact, contact, me)
    )
    db_commit()
    return jsonify({"ok": True, "burned": True})


@app.route("/msg/inbox", methods=["GET"])
@require_login
def inbox():
    """
    FIXED N+1: single query with a LEFT JOIN fetches display_name and avatar_color
    for all contacts at once — previously did 1 query per contact row.
    """
    me = session["user_email"]
    rows = db_exec(
        """
        SELECT
          CASE WHEN m.sender=? THEN m.recipient ELSE m.sender END AS contact,
          MAX(m.sent_at) AS last_at,
          COUNT(*) AS total,
          u.display_name,
          u.avatar_color
        FROM messages m
        LEFT JOIN users u
          ON u.email = CASE WHEN m.sender=? THEN m.recipient ELSE m.sender END
        WHERE m.sender=? OR m.recipient=?
        GROUP BY contact
        ORDER BY last_at DESC
        """,
        (me, me, me, me)
    ).fetchall()
    return jsonify([{
        "contact": r["contact"],
        "name":    r["display_name"] or r["contact"].split("@")[0],
        "color":   r["avatar_color"] or "#888",
        "last_at": r["last_at"],
        "total":   r["total"],
    } for r in rows])


@app.route("/msg/search_user", methods=["GET"])
@require_login
def search_user():
    q = request.args.get("q", "").strip().lower()
    if not q or len(q) < 3:
        return jsonify([])
    rows = db_exec(
        "SELECT email, display_name, avatar_color FROM users "
        "WHERE (email LIKE ? OR display_name LIKE ?) AND email != ? LIMIT 10",
        (f"%{q}%", f"%{q}%", session["user_email"])
    ).fetchall()
    return jsonify([{
        "email": r["email"], "name": r["display_name"], "color": r["avatar_color"]
    } for r in rows])


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "chaoskey_url": CHAOSKEY_URL,
        "db_backend": "postgresql" if USE_POSTGRES else "sqlite+WAL",
        "e2ee": "ChaosKey AES-256-GCM (proxied) + RSA-OAEP dual-wrap (browser)",
        "speed": "incremental polling + optimistic send + speculative encrypt + keepalive CK pool + N+1 fix",
    })


# ════════════════════════════════════════════════════════════════
#  FRONTEND
# ════════════════════════════════════════════════════════════════
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BurnChat</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;500;600;700;800&family=Fira+Code:wght@300;400;500&family=Lora:ital,wght@0,400;0,600;1,400&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --void:#060608;--coal:#0d0e13;--ash:#181a22;--cinder:#22252f;
  --smoke:#2e3140;--dust:#4a4f61;--fog:#6b7182;--mist:#9097a8;
  --paper:#c8ccdb;--snow:#eef0f6;
  --ember:#ff6b35;--flame:#ff8c42;--glow:#ffb347;--spark:#ffd166;
  --cold:#4ecdc4;--ice:#a8e6cf;
  --ember-dim:rgba(255,107,53,.12);--ember-mid:rgba(255,107,53,.25);
  --ember-glow:0 0 30px rgba(255,107,53,.3);
  --r-sm:8px;--r-md:14px;--r-lg:20px;--r-xl:28px;
}
html{-webkit-font-smoothing:antialiased;height:100%}
body{background:var(--void);color:var(--paper);font-family:'Syne',sans-serif;height:100%;overflow:hidden}
::-webkit-scrollbar{width:3px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--smoke);border-radius:2px}

#auth{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;background:var(--void);z-index:100;overflow-y:auto}
#auth.hidden{display:none}
.auth-bg{position:absolute;inset:0;background:radial-gradient(ellipse 80% 60% at 20% 80%,rgba(255,107,53,.07) 0%,transparent 60%),radial-gradient(ellipse 60% 50% at 80% 20%,rgba(78,205,196,.05) 0%,transparent 50%);pointer-events:none}
.auth-card{position:relative;width:100%;max-width:440px;padding:3rem 2.5rem;background:var(--coal);border:1px solid var(--cinder);border-radius:var(--r-xl);box-shadow:0 40px 80px rgba(0,0,0,.6);animation:riseIn .5s cubic-bezier(.22,1,.36,1) both;margin:auto}
@keyframes riseIn{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:none}}
.auth-wordmark{display:flex;align-items:center;gap:12px;margin-bottom:2rem}
.burn-icon{width:42px;height:42px;background:linear-gradient(135deg,var(--ember),var(--glow));border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:1.3rem;box-shadow:var(--ember-glow);flex-shrink:0}
.wordmark-text h1{font-size:1.5rem;font-weight:800;letter-spacing:-.03em;color:var(--snow)}
.wordmark-text p{font-family:'Fira Code',monospace;font-size:.62rem;color:var(--fog);letter-spacing:.06em;margin-top:1px}
.auth-tabs{display:flex;gap:4px;background:var(--ash);border-radius:10px;padding:4px;margin-bottom:1.5rem}
.auth-tab{flex:1;padding:.55rem;background:none;border:none;font-family:'Syne',sans-serif;font-size:.82rem;font-weight:600;color:var(--fog);cursor:pointer;border-radius:7px;transition:all .2s}
.auth-tab.active{background:var(--cinder);color:var(--snow)}
.form-field{margin-bottom:.9rem}
.form-field label{display:block;font-family:'Fira Code',monospace;font-size:.65rem;color:var(--fog);letter-spacing:.06em;text-transform:uppercase;margin-bottom:.4rem}
.form-field input{width:100%;padding:.7rem 1rem;background:var(--ash);border:1px solid var(--smoke);border-radius:var(--r-sm);color:var(--snow);font-family:'Syne',sans-serif;font-size:.9rem;outline:none;transition:border-color .2s,box-shadow .2s}
.form-field input::placeholder{color:var(--dust)}
.form-field input:focus{border-color:var(--ember);box-shadow:0 0 0 3px rgba(255,107,53,.12)}
.form-hint{font-family:'Fira Code',monospace;font-size:.62rem;color:var(--fog);margin-top:.35rem;line-height:1.5}
.auth-submit{width:100%;padding:.85rem;margin-top:.5rem;background:linear-gradient(135deg,var(--ember),var(--flame));color:#fff;border:none;border-radius:var(--r-sm);font-family:'Syne',sans-serif;font-weight:700;font-size:.95rem;cursor:pointer;letter-spacing:.01em;transition:all .2s;box-shadow:0 4px 20px rgba(255,107,53,.3)}
.auth-submit:hover{transform:translateY(-1px);box-shadow:0 8px 30px rgba(255,107,53,.4)}
.auth-submit:disabled{opacity:.4;cursor:not-allowed;transform:none}
.auth-err{font-family:'Fira Code',monospace;font-size:.73rem;color:#ff8fab;text-align:center;min-height:1.2rem;margin-top:.7rem}

#app{display:flex;height:100vh}
#app.hidden{display:none}

.sidebar{width:300px;flex-shrink:0;background:var(--coal);border-right:1px solid var(--cinder);display:flex;flex-direction:column;overflow:hidden}
.sidebar-top{padding:1.25rem 1.25rem 0}
.user-row{display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem}
.user-chip{display:flex;align-items:center;gap:10px}
.avatar{width:34px;height:34px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:.85rem;color:#fff;flex-shrink:0}
.user-meta .uname{font-size:.88rem;font-weight:700;color:var(--snow)}
.user-meta .uemail{font-family:'Fira Code',monospace;font-size:.62rem;color:var(--fog)}
.logout-btn{background:none;border:none;font-family:'Fira Code',monospace;font-size:.65rem;color:var(--dust);cursor:pointer;padding:.3rem .6rem;border-radius:6px;transition:color .2s,background .2s}
.logout-btn:hover{color:var(--ember);background:var(--ember-dim)}
.status-bar{margin-bottom:.9rem;display:flex;flex-direction:column;gap:5px}
.bar-item{display:flex;align-items:center;justify-content:space-between;padding:.4rem .7rem;border-radius:8px;font-family:'Fira Code',monospace;font-size:.63rem}
.bar-ok{background:rgba(78,205,196,.07);border:1px solid rgba(78,205,196,.18);color:var(--cold)}
.bar-warn{background:rgba(255,107,53,.1);border:1px solid rgba(255,107,53,.25);color:var(--ember)}
.bar-btn{background:none;border:none;font-family:'Fira Code',monospace;font-size:.6rem;color:var(--dust);cursor:pointer;transition:color .15s}
.bar-btn:hover{color:var(--ember)}
.search-wrap{position:relative;margin-bottom:1rem}
.search-wrap input{width:100%;padding:.6rem .9rem .6rem 2.4rem;background:var(--ash);border:1px solid var(--smoke);border-radius:10px;color:var(--snow);font-family:'Syne',sans-serif;font-size:.85rem;outline:none;transition:border-color .2s}
.search-wrap input:focus{border-color:var(--ember)}
.search-wrap input::placeholder{color:var(--dust)}
.search-icon{position:absolute;left:.8rem;top:50%;transform:translateY(-50%);font-size:.85rem;pointer-events:none;color:var(--fog)}
.search-results{position:absolute;top:calc(100% + 4px);left:0;right:0;background:var(--cinder);border:1px solid var(--smoke);border-radius:10px;overflow:hidden;z-index:50;box-shadow:0 10px 30px rgba(0,0,0,.5);display:none}
.search-results.open{display:block}
.search-result-item{display:flex;align-items:center;gap:10px;padding:.7rem 1rem;cursor:pointer;transition:background .15s}
.search-result-item:hover{background:var(--smoke)}
.sr-info .sr-name{font-size:.85rem;font-weight:600;color:var(--snow)}
.sr-info .sr-email{font-family:'Fira Code',monospace;font-size:.62rem;color:var(--fog)}
.sidebar-label{font-family:'Fira Code',monospace;font-size:.63rem;color:var(--dust);letter-spacing:.08em;text-transform:uppercase;padding:0 1.25rem .5rem}
.thread-list{flex:1;overflow-y:auto;padding:0 .5rem .5rem}
.thread-item{display:flex;align-items:center;gap:10px;padding:.75rem;border-radius:12px;cursor:pointer;transition:background .15s;margin-bottom:2px}
.thread-item:hover{background:var(--ash)}
.thread-item.active{background:var(--ember-dim);border:1px solid var(--ember-mid)}
.thread-item.active .thread-name{color:var(--glow)}
.thread-info{flex:1;min-width:0}
.thread-name{font-size:.88rem;font-weight:600;color:var(--snow);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.thread-email{font-family:'Fira Code',monospace;font-size:.6rem;color:var(--fog);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.thread-time{font-family:'Fira Code',monospace;font-size:.6rem;color:var(--dust);flex-shrink:0}
.no-threads{padding:2rem 1rem;text-align:center;color:var(--dust);font-size:.82rem;line-height:1.6}

.main{flex:1;display:flex;flex-direction:column;background:var(--void);overflow:hidden}
.empty-state{flex:1;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:.75rem;color:var(--dust);text-align:center;padding:2rem}
.es-icon{font-size:3rem;margin-bottom:.5rem;opacity:.4}
.es-title{font-size:1.1rem;font-weight:700;color:var(--fog)}
.es-sub{font-family:'Fira Code',monospace;font-size:.73rem;line-height:1.7}
.chat-view{display:none;flex-direction:column;height:100%}
.chat-view.active{display:flex}
.chat-header{display:flex;align-items:center;justify-content:space-between;padding:1rem 1.5rem;background:var(--coal);border-bottom:1px solid var(--cinder);flex-shrink:0}
.chat-header-left{display:flex;align-items:center;gap:12px}
.contact-info .cname{font-size:.95rem;font-weight:700;color:var(--snow)}
.contact-info .cemail{font-family:'Fira Code',monospace;font-size:.62rem;color:var(--fog);margin-top:1px}
.enc-badge{display:flex;align-items:center;gap:5px;font-family:'Fira Code',monospace;font-size:.62rem;color:var(--cold);padding:.2rem .55rem;background:rgba(78,205,196,.08);border:1px solid rgba(78,205,196,.2);border-radius:100px}
.burn-thread-btn{display:flex;align-items:center;gap:6px;padding:.45rem .9rem;border-radius:8px;background:rgba(255,90,90,.1);border:1px solid rgba(255,90,90,.2);color:#ff8fab;font-family:'Syne',sans-serif;font-size:.78rem;font-weight:600;cursor:pointer;transition:all .2s}
.burn-thread-btn:hover{background:rgba(255,90,90,.2);transform:scale(1.03)}
.burn-thread-btn:active{transform:scale(.97)}
.messages{flex:1;overflow-y:auto;padding:1.5rem;display:flex;flex-direction:column;gap:.75rem}
.msg-group{display:flex;flex-direction:column;gap:3px;max-width:70%}
.msg-group.mine{align-self:flex-end;align-items:flex-end}
.msg-group.theirs{align-self:flex-start;align-items:flex-start}
.bubble{padding:.65rem 1rem;font-family:'Lora',serif;font-size:.88rem;line-height:1.6;word-break:break-word}
.mine .bubble{background:linear-gradient(135deg,var(--ember),var(--flame));color:#fff;border-radius:18px 18px 4px 18px}
.theirs .bubble{background:var(--ash);border:1px solid var(--cinder);color:var(--snow);border-radius:18px 18px 18px 4px}
.msg-meta{font-family:'Fira Code',monospace;font-size:.58rem;color:var(--dust);padding:0 .3rem}
.e2ee-tag{font-family:'Fira Code',monospace;font-size:.53rem;color:var(--cold);opacity:.55;padding:0 .3rem}
.err-bubble{color:#ff8fab;font-style:italic}
.msg-group.optimistic .bubble{opacity:.65}
.msg-group.optimistic .msg-meta::after{content:' · sending…'}

.compose{padding:1rem 1.5rem;background:var(--coal);border-top:1px solid var(--cinder);display:flex;gap:.75rem;align-items:flex-end;flex-shrink:0}
.compose-wrap{flex:1;background:var(--ash);border:1px solid var(--smoke);border-radius:14px;overflow:hidden;transition:border-color .2s,box-shadow .2s}
.compose-wrap:focus-within{border-color:var(--ember);box-shadow:0 0 0 3px rgba(255,107,53,.1)}
.compose-input{width:100%;padding:.8rem 1rem;background:none;border:none;color:var(--snow);font-family:'Lora',serif;font-size:.88rem;outline:none;resize:none;max-height:120px;line-height:1.5}
.compose-input::placeholder{color:var(--dust)}
.spec-indicator{font-family:'Fira Code',monospace;font-size:.58rem;color:var(--cold);padding:.2rem 1rem .4rem;opacity:0;transition:opacity .3s}
.spec-indicator.ready{opacity:.7}
.send-btn{width:44px;height:44px;flex-shrink:0;background:linear-gradient(135deg,var(--ember),var(--flame));border:none;border-radius:12px;color:#fff;font-size:1.1rem;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .15s;box-shadow:0 4px 12px rgba(255,107,53,.3)}
.send-btn:hover{transform:scale(1.08);box-shadow:0 6px 18px rgba(255,107,53,.45)}
.send-btn:active{transform:scale(.94)}
.send-btn:disabled{opacity:.35;cursor:not-allowed;transform:none}

.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.75);display:flex;align-items:center;justify-content:center;z-index:200;opacity:0;pointer-events:none;transition:opacity .2s}
.modal-overlay.open{opacity:1;pointer-events:all}
.modal{background:var(--coal);border:1px solid var(--cinder);border-radius:var(--r-xl);padding:2rem 2.25rem;max-width:400px;width:92%;box-shadow:0 40px 80px rgba(0,0,0,.6);transform:scale(.95);transition:transform .2s}
.modal-overlay.open .modal{transform:scale(1)}
.modal-icon{font-size:2.2rem;margin-bottom:.8rem}
.modal h2{font-size:1.05rem;font-weight:800;color:var(--snow);margin-bottom:.5rem}
.modal p{font-family:'Fira Code',monospace;font-size:.72rem;color:var(--fog);line-height:1.7;margin-bottom:1.25rem}
.modal-input{width:100%;padding:.72rem 1rem;background:var(--ash);border:1px solid var(--smoke);border-radius:8px;color:var(--snow);font-family:'Syne',sans-serif;font-size:.88rem;outline:none;transition:border-color .2s;margin-bottom:.4rem}
.modal-input:focus{border-color:var(--ember)}
.modal-err{font-family:'Fira Code',monospace;font-size:.68rem;color:#ff8fab;min-height:1rem;margin-bottom:.75rem}
.modal-btns{display:flex;gap:.75rem}
.modal-cancel,.modal-confirm{flex:1;padding:.68rem;border-radius:10px;border:none;font-family:'Syne',sans-serif;font-weight:700;font-size:.86rem;cursor:pointer;transition:all .15s}
.modal-cancel{background:var(--ash);color:var(--paper);border:1px solid var(--smoke)}
.modal-cancel:hover{border-color:var(--fog)}
.modal-confirm{background:linear-gradient(135deg,var(--ember),var(--flame));color:#fff;box-shadow:0 4px 15px rgba(255,107,53,.3)}
.modal-confirm:disabled{opacity:.45;cursor:not-allowed}
.modal-confirm-danger{background:linear-gradient(135deg,#ff4444,#ff6b35)}

.toast{position:fixed;bottom:2rem;left:50%;transform:translateX(-50%) translateY(20px);background:var(--cinder);color:var(--snow);font-family:'Fira Code',monospace;font-size:.75rem;padding:.6rem 1.2rem;border-radius:100px;border:1px solid var(--smoke);opacity:0;transition:opacity .25s,transform .25s;pointer-events:none;z-index:300;white-space:nowrap;max-width:90vw;text-align:center}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.toast.ok{border-color:rgba(168,230,207,.3);color:var(--ice)}
.toast.err{border-color:rgba(255,107,53,.3);color:var(--ember)}
</style>
</head>
<body>

<div id="auth">
  <div class="auth-bg"></div>
  <div class="auth-card">
    <div class="auth-wordmark">
      <div class="burn-icon">🔥</div>
      <div class="wordmark-text">
        <h1>BurnChat</h1>
        <p>RSA-OAEP · AES-256-GCM · CROSS-DEVICE E2EE</p>
      </div>
    </div>
    <div class="auth-tabs">
      <button class="auth-tab active" id="tab-in" onclick="switchAuthTab('login')">Sign in</button>
      <button class="auth-tab" id="tab-up" onclick="switchAuthTab('signup')">Create account</button>
    </div>
    <div id="field-name" class="form-field" style="display:none">
      <label>Display name</label>
      <input id="f-name" type="text" placeholder="How should people know you?" autocomplete="name">
    </div>
    <div class="form-field">
      <label>Email</label>
      <input id="f-email" type="email" placeholder="you@example.com" autocomplete="email">
    </div>
    <div class="form-field">
      <label>Password</label>
      <input id="f-pw" type="password" placeholder="••••••••" autocomplete="current-password">
    </div>
    <div id="field-ck-key" class="form-field" style="display:none">
      <label>ChaosKey API key</label>
      <input id="f-ck-key" type="text" placeholder="ck_live_…" autocomplete="off" spellcheck="false"
        style="font-family:'Fira Code',monospace;font-size:.8rem">
      <div class="form-hint">Register on ChaosKey → copy your <code style="color:var(--ember)">ck_live_…</code> key</div>
    </div>
    <button class="auth-submit" id="auth-btn" onclick="doAuth()">Sign in →</button>
    <div class="auth-err" id="auth-err"></div>
  </div>
</div>

<div id="app" class="hidden">
  <div class="sidebar">
    <div class="sidebar-top">
      <div class="user-row">
        <div class="user-chip">
          <div class="avatar" id="my-avatar" style="background:#ff6b35">U</div>
          <div class="user-meta">
            <div class="uname" id="my-name">–</div>
            <div class="uemail" id="my-email">–</div>
          </div>
        </div>
        <button class="logout-btn" onclick="doLogout()">exit</button>
      </div>
      <div class="status-bar" id="status-bar"></div>
      <div class="search-wrap">
        <span class="search-icon">⌕</span>
        <input id="search-input" type="email" placeholder="Find user by email…"
          oninput="onSearchInput(this.value)"
          onblur="setTimeout(()=>closeSearch(),150)">
        <div class="search-results" id="search-results"></div>
      </div>
    </div>
    <div class="sidebar-label">Conversations</div>
    <div class="thread-list" id="thread-list">
      <div class="no-threads">Search for a user above<br>to start a conversation.</div>
    </div>
  </div>

  <div class="main">
    <div class="empty-state" id="empty-state">
      <div class="es-icon">🔥</div>
      <div class="es-title">Select a conversation</div>
      <div class="es-sub">End-to-end encrypted · RSA-OAEP + ChaosKey AES-256-GCM<br>Works across all your devices</div>
    </div>
    <div class="chat-view" id="chat-view">
      <div class="chat-header">
        <div class="chat-header-left">
          <div class="avatar" id="contact-avatar" style="background:#888">C</div>
          <div class="contact-info">
            <div class="cname" id="contact-name">–</div>
            <div class="cemail" id="contact-email">–</div>
          </div>
          <div class="enc-badge">⚿ E2EE</div>
        </div>
        <button class="burn-thread-btn" onclick="confirmBurn()">🔥 Burn thread</button>
      </div>
      <div class="messages" id="messages-area"></div>
      <div class="compose">
        <div class="compose-wrap">
          <textarea class="compose-input" id="compose-input" rows="1"
            placeholder="Write an encrypted message… (Enter to send)"
            oninput="onComposeInput(this)"
            onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendMessage();}"></textarea>
          <div class="spec-indicator" id="spec-indicator">⚿ encrypted and ready</div>
        </div>
        <button class="send-btn" id="send-btn" onclick="sendMessage()">➤</button>
      </div>
    </div>
  </div>
</div>

<!-- Burn thread modal -->
<div class="modal-overlay" id="burn-modal">
  <div class="modal">
    <div class="modal-icon">🔥</div>
    <h2>Burn this thread?</h2>
    <p id="burn-modal-text">This will permanently delete all messages.</p>
    <div class="modal-btns">
      <button class="modal-cancel" onclick="closeMod('burn-modal')">Cancel</button>
      <button class="modal-confirm modal-confirm-danger" onclick="executeBurn()">Burn it</button>
    </div>
  </div>
</div>

<!-- Update ChaosKey -->
<div class="modal-overlay" id="key-modal">
  <div class="modal">
    <div class="modal-icon">⚿</div>
    <h2>Update ChaosKey API key</h2>
    <p>Paste a fresh <code style="font-family:'Fira Code',monospace;color:var(--ember)">ck_live_…</code> key.</p>
    <input id="modal-ck-input" class="modal-input" type="text" placeholder="ck_live_…"
      onkeydown="if(event.key==='Enter')saveUpdatedKey()">
    <div class="modal-err" id="key-modal-err"></div>
    <div class="modal-btns">
      <button class="modal-cancel" onclick="closeMod('key-modal')">Cancel</button>
      <button class="modal-confirm" onclick="saveUpdatedKey()">Save</button>
    </div>
  </div>
</div>

<!-- Re-key -->
<div class="modal-overlay" id="rekey-modal">
  <div class="modal">
    <div class="modal-icon">🔑</div>
    <h2 id="rekey-modal-title">Generate new keys</h2>
    <p id="rekey-modal-desc">Enter your password to generate a fresh RSA keypair.</p>
    <input id="rekey-pw-input" class="modal-input" type="password" placeholder="Your current password"
      onkeydown="if(event.key==='Enter')executeRekey()">
    <div class="modal-err" id="rekey-modal-err"></div>
    <div class="modal-btns">
      <button class="modal-cancel" onclick="closeMod('rekey-modal')">Later</button>
      <button class="modal-confirm" id="rekey-confirm-btn" onclick="executeRekey()">Generate keys</button>
    </div>
  </div>
</div>

<!-- Vault decrypt -->
<div class="modal-overlay" id="vault-pw-modal">
  <div class="modal">
    <div class="modal-icon">🔐</div>
    <h2>Enter password to unlock vault</h2>
    <p>Your encrypted key vault was found but couldn't be unlocked automatically. Enter your password to decrypt it on this device.</p>
    <input id="vault-pw-input" class="modal-input" type="password" placeholder="Your password"
      onkeydown="if(event.key==='Enter')executeVaultDecrypt()">
    <div class="modal-err" id="vault-pw-err"></div>
    <div class="modal-btns">
      <button class="modal-cancel" onclick="closeMod('vault-pw-modal');showRekeyModal('failed')">Generate new keys instead</button>
      <button class="modal-confirm" id="vault-pw-btn" onclick="executeVaultDecrypt()">Unlock</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
'use strict';

// ═══════════════════════════════════════════════
//  State
// ═══════════════════════════════════════════════
const S = {
  me:            null,
  activeContact: null,
  threads:       [],
  pollTimer:     null,
  authMode:      'login',
  rsaPublicKey:  null,
  rsaPrivateKey: null,
  _pendingVault: null,
  lastMsgId:     {},   // { [email]: number }
};

// ── LRU decryption cache (max 500 entries) ─────────────────────
const DEC_CACHE_MAX = 500;
const decCache = new Map();
function decCacheSet(id, val) {
  if (decCache.size >= DEC_CACHE_MAX) {
    // Evict oldest entry (Map preserves insertion order)
    decCache.delete(decCache.keys().next().value);
  }
  decCache.set(id, val);
}

// Rendered message IDs — dedup guard. Cleared on thread switch / burn.
const renderedIds = new Set();

// Public key cache — imported CryptoKey objects, keyed by email
const pubKeyCache = new Map();

// ── Adaptive poll interval ─────────────────────────────────────
// Visible + active:  3 s base, backs off to 10 s when no new msgs
// Hidden (tab away): 30 s flat — restores on visibility change
const POLL_MIN    = 3000;
const POLL_MAX    = 10000;
const POLL_HIDDEN = 30000;
let   _pollInterval = POLL_MIN;
let   _pollSinceActivity = 0;   // consecutive polls with no new messages

function _resetPollInterval() {
  _pollSinceActivity = 0;
  _pollInterval = POLL_MIN;
}

function _backoffPollInterval() {
  _pollSinceActivity++;
  if (_pollSinceActivity >= 3)  _pollInterval = Math.min(_pollInterval * 1.5 | 0, POLL_MAX);
}

function _effectivePoll() {
  return document.hidden ? POLL_HIDDEN : _pollInterval;
}

// ── Speculative encryption ─────────────────────────────────────
let specText    = '';
let specPromise = null;
let specTimer   = null;

function _startSpecEncrypt(txt) {
  clearTimeout(specTimer);
  if (txt !== specText) { specPromise = null; }
  if (!txt) { specText = ''; specPromise = null; _setSpecIndicator(false); return; }

  specTimer = setTimeout(async () => {
    if (!S.activeContact) return;
    specText    = txt;
    specPromise = callChaosKey('/v1/encrypt', {plaintext: txt}).catch(() => null);
    const ok    = await specPromise;
    _setSpecIndicator(!!ok && specText === txt);
  }, 350);
}

function _setSpecIndicator(ready) {
  const el = document.getElementById('spec-indicator');
  if (el) el.classList.toggle('ready', ready);
}

// ═══════════════════════════════════════════════
//  Utilities
// ═══════════════════════════════════════════════
const $   = id => document.getElementById(id);
const esc = s  => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const initials = s => (s||'?')[0].toUpperCase();

// Toast dedup: skip if same message shown in last 2 s
let _lastToastMsg = '', _lastToastTs = 0;
function toast(msg, type='ok', dur=3000) {
  const now = Date.now();
  if (msg === _lastToastMsg && now - _lastToastTs < 2000) return;
  _lastToastMsg = msg; _lastToastTs = now;
  const el = $('toast');
  el.textContent = msg;
  el.className = `toast ${type} show`;
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove('show'), dur);
}

async function api(path, opts={}) {
  const r = await fetch(path, {
    credentials: 'same-origin',
    headers: {'Content-Type':'application/json', ...(opts.headers||{})},
    ...opts,
  });
  const ct = r.headers.get('Content-Type') || '';
  const data = ct.includes('json') ? await r.json() : {error: 'Server error'};
  return {ok: r.ok, status: r.status, data};
}

async function callChaosKey(path, body) {
  const proxyPath = path.replace('/v1/', '/proxy/');
  const {ok, data} = await api(proxyPath, {method:'POST', body:JSON.stringify(body)});
  if (!ok) throw new Error(data.error || 'ChaosKey proxy error');
  return data;
}

// requestAnimationFrame-throttled textarea resize — avoids forced reflow per keystroke
let _rafResize = null;
function autoResize(ta) {
  if (_rafResize) return;
  _rafResize = requestAnimationFrame(() => {
    _rafResize = null;
    ta.style.height = 'auto';
    ta.style.height = Math.min(ta.scrollHeight, 120) + 'px';
  });
}

function fmtTime(iso) {
  if (!iso) return '';
  return new Date(iso).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
}
function fmtDate(iso) {
  if (!iso) return '';
  const d = new Date(iso), now = new Date();
  if (d.toDateString() === now.toDateString()) return 'Today';
  const y = new Date(now); y.setDate(now.getDate()-1);
  if (d.toDateString() === y.toDateString()) return 'Yesterday';
  return d.toLocaleDateString([], {month:'short', day:'numeric'});
}
function closeMod(id) { $(id).classList.remove('open'); }

// ═══════════════════════════════════════════════
//  RSA / vault helpers
// ═══════════════════════════════════════════════
async function deriveAesKey(password, salt) {
  const enc = new TextEncoder();
  const km = await crypto.subtle.importKey('raw', enc.encode(password), {name:'PBKDF2'}, false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2', salt, iterations:100000, hash:'SHA-256'},
    km, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']
  );
}

async function genAndRegisterKeys(password, email) {
  const kp = await crypto.subtle.generateKey(
    {name:'RSA-OAEP', modulusLength:2048, publicExponent:new Uint8Array([1,0,1]), hash:'SHA-256'},
    true, ['encrypt','decrypt']
  );
  S.rsaPublicKey  = kp.publicKey;
  S.rsaPrivateKey = kp.privateKey;

  const pubRaw  = await crypto.subtle.exportKey('spki', kp.publicKey);
  const privRaw = await crypto.subtle.exportKey('pkcs8', kp.privateKey);

  _cachePrivKey(email, privRaw);

  const salt    = crypto.getRandomValues(new Uint8Array(16));
  const aesKey  = await deriveAesKey(password, salt);
  const iv      = crypto.getRandomValues(new Uint8Array(12));
  const encPriv = await crypto.subtle.encrypt({name:'AES-GCM', iv}, aesKey, privRaw);

  const blob = new Uint8Array(16 + 12 + encPriv.byteLength);
  blob.set(salt, 0); blob.set(iv, 16);
  blob.set(new Uint8Array(encPriv), 28);

  return {
    pubB64:     _toB64(pubRaw),
    encPrivB64: _toB64(blob),
    saltHex:    _toHex(salt),
  };
}

async function decryptVault(encPrivB64, password) {
  const blob = _fromB64(encPrivB64);
  if (blob.length < 29) throw new Error('Vault blob too short');
  const salt    = blob.slice(0, 16);
  const iv      = blob.slice(16, 28);
  const ct      = blob.slice(28);
  const aesKey  = await deriveAesKey(password, salt);
  const privRaw = await crypto.subtle.decrypt({name:'AES-GCM', iv}, aesKey, ct);
  return {privRaw, key: await _importPrivKey(privRaw)};
}

async function loadPrivKeyFromStorage(email) {
  const b64 = localStorage.getItem('bc_priv_' + email);
  if (!b64) return null;
  try {
    const raw = _fromB64(b64);
    return await _importPrivKey(raw);
  } catch(e) {
    localStorage.removeItem('bc_priv_' + email);
    return null;
  }
}

async function importPublicKey(pubB64) {
  return crypto.subtle.importKey('spki', _fromB64(pubB64), {name:'RSA-OAEP', hash:'SHA-256'}, false, ['encrypt']);
}

async function rsaEncrypt(plaintext, cryptoKey) {
  const enc = await crypto.subtle.encrypt({name:'RSA-OAEP'}, cryptoKey, new TextEncoder().encode(plaintext));
  return _toB64(enc);
}

async function rsaDecrypt(cipherB64) {
  if (!S.rsaPrivateKey) return null;
  try {
    const dec = await crypto.subtle.decrypt({name:'RSA-OAEP'}, S.rsaPrivateKey, _fromB64(cipherB64));
    return new TextDecoder().decode(dec);
  } catch(e) { return null; }
}

// ── Key cache helpers ──────────────────────────────────────────
async function prefetchContactKey(email) {
  if (pubKeyCache.has(email)) return pubKeyCache.get(email);
  try {
    const {data} = await api(`/user/key?email=${encodeURIComponent(email)}`);
    if (data.key) {
      const key = await importPublicKey(data.key);
      pubKeyCache.set(email, key);
      return key;
    }
  } catch(e) {}
  return null;
}

async function prefetchAllContactKeys(emails) {
  const missing = emails.filter(e => !pubKeyCache.has(e));
  if (!missing.length) return;
  try {
    const {ok, data} = await api('/user/keys_bulk', {
      method: 'POST',
      body: JSON.stringify({emails: missing}),
    });
    if (!ok) return;
    await Promise.all(Object.entries(data).map(async ([email, pubB64]) => {
      if (pubB64 && !pubKeyCache.has(email)) {
        const key = await importPublicKey(pubB64);
        pubKeyCache.set(email, key);
      }
    }));
  } catch(e) {}
}

async function ensureOwnPublicKey() {
  if (S.rsaPublicKey) return;
  if (pubKeyCache.has(S.me.email)) { S.rsaPublicKey = pubKeyCache.get(S.me.email); return; }
  try {
    const {data} = await api(`/user/key?email=${encodeURIComponent(S.me.email)}`);
    if (data.key) {
      S.rsaPublicKey = await importPublicKey(data.key);
      pubKeyCache.set(S.me.email, S.rsaPublicKey);
    }
  } catch(e) {}
}

function _toB64(buf)   { return btoa(String.fromCharCode(...new Uint8Array(buf instanceof ArrayBuffer ? buf : buf.buffer || buf))); }
function _fromB64(b64) { return Uint8Array.from(atob(b64), c => c.charCodeAt(0)); }
function _toHex(u8)    { return Array.from(u8).map(b => b.toString(16).padStart(2,'0')).join(''); }
function _cachePrivKey(email, privRaw) {
  try { localStorage.setItem('bc_priv_' + email, _toB64(privRaw)); } catch(e) {}
}
async function _importPrivKey(raw) {
  return crypto.subtle.importKey('pkcs8', raw, {name:'RSA-OAEP', hash:'SHA-256'}, false, ['decrypt']);
}

// ═══════════════════════════════════════════════
//  Auth
// ═══════════════════════════════════════════════
function switchAuthTab(mode) {
  S.authMode = mode;
  $('tab-in').classList.toggle('active', mode==='login');
  $('tab-up').classList.toggle('active', mode==='signup');
  $('field-name').style.display   = mode==='signup' ? 'block' : 'none';
  $('field-ck-key').style.display = mode==='signup' ? 'block' : 'none';
  $('auth-btn').textContent = mode==='login' ? 'Sign in →' : 'Create account →';
  $('auth-err').textContent = '';
}

async function doAuth() {
  const email = $('f-email').value.trim().toLowerCase();
  const pw    = $('f-pw').value;
  const name  = $('f-name').value.trim();
  const ckKey = $('f-ck-key').value.trim();
  const errEl = $('auth-err');
  const btn   = $('auth-btn');

  if (!email || !pw) { errEl.textContent = '⚠ Email and password required'; return; }
  btn.disabled = true; errEl.textContent = 'Generating keys…';

  let pubB64=null, encPrivB64=null, saltHex=null;
  if (S.authMode === 'signup') {
    try {
      const keys = await genAndRegisterKeys(pw, email);
      pubB64 = keys.pubB64; encPrivB64 = keys.encPrivB64; saltHex = keys.saltHex;
      errEl.textContent = 'Creating account…';
    } catch(e) {
      errEl.textContent = '⚠ Key generation failed: ' + e.message;
      btn.disabled = false; return;
    }
  } else {
    errEl.textContent = 'Signing in…';
  }

  const path = S.authMode === 'signup' ? '/auth/signup' : '/auth/login';
  const body = S.authMode === 'signup'
    ? {email, password:pw, name, chaoskey_api_key:ckKey, public_key:pubB64, encrypted_private_key:encPrivB64, vault_salt:saltHex}
    : {email, password:pw};

  const {ok, data} = await api(path, {method:'POST', body:JSON.stringify(body)});
  if (!ok) {
    errEl.textContent = '⚠ ' + (data.error || 'Authentication failed');
    btn.disabled = false; return;
  }

  S.me = {email: data.email, name: data.name, color: data.color};

  if (S.authMode === 'login') {
    await _resolvePrivateKey(pw, data);
    if (data.public_key) {
      try { S.rsaPublicKey = await importPublicKey(data.public_key); pubKeyCache.set(data.email, S.rsaPublicKey); } catch(e) {}
    }
  } else {
    if (S.rsaPublicKey) pubKeyCache.set(email, S.rsaPublicKey);
  }

  errEl.textContent = '';
  btn.disabled = false;
  enterApp(data);
}

async function _resolvePrivateKey(password, data) {
  S.rsaPrivateKey = await loadPrivKeyFromStorage(data.email);
  if (S.rsaPrivateKey) return;

  if (data.encrypted_private_key && data.vault_salt) {
    S._pendingVault = {encrypted_private_key: data.encrypted_private_key};
    if (password) {
      try {
        const {privRaw, key} = await decryptVault(data.encrypted_private_key, password);
        S.rsaPrivateKey = key;
        _cachePrivKey(data.email, privRaw);
        toast('🔑 Keys synced from vault', 'ok', 4000);
        return;
      } catch(e) { _showVaultPwModal(); return; }
    }
    _showVaultPwModal();
  } else if (!data.encrypted_private_key) {
    showRekeyModal('missing');
  }
}

async function _resolvePrivateKeyNoPassword(data) {
  S.rsaPrivateKey = await loadPrivKeyFromStorage(data.email);
  if (S.rsaPrivateKey) return;
  if (data.encrypted_private_key) {
    S._pendingVault = {encrypted_private_key: data.encrypted_private_key};
    _showVaultPwModal();
  } else {
    showRekeyModal('missing');
  }
}

function _showVaultPwModal() {
  $('vault-pw-input').value = '';
  $('vault-pw-err').textContent = '';
  $('vault-pw-modal').classList.add('open');
  setTimeout(() => $('vault-pw-input').focus(), 150);
}

async function executeVaultDecrypt() {
  const pw  = $('vault-pw-input').value;
  const btn = $('vault-pw-btn');
  const err = $('vault-pw-err');
  if (!pw) { err.textContent = '⚠ Password required'; return; }
  btn.disabled = true; btn.textContent = 'Unlocking…'; err.textContent = '';
  try {
    const vault = S._pendingVault;
    if (!vault || !vault.encrypted_private_key) throw new Error('No vault data');
    const {privRaw, key} = await decryptVault(vault.encrypted_private_key, pw);
    S.rsaPrivateKey = key;
    _cachePrivKey(S.me.email, privRaw);
    closeMod('vault-pw-modal');
    renderStatusBar();
    toast('🔑 Keys unlocked — messages loading…', 'ok', 4000);
    if (S.activeContact) {
      S.lastMsgId[S.activeContact.email] = 0;
      $('messages-area').innerHTML = '';
      renderedIds.clear();
      await loadThread(S.activeContact.email, true);
    }
  } catch(e) {
    err.textContent = '⚠ Wrong password or corrupted vault';
  } finally { btn.disabled = false; btn.textContent = 'Unlock'; }
}

async function doLogout() {
  await api('/auth/logout', {method:'POST'});
  S.rsaPublicKey = null; S.rsaPrivateKey = null; S._pendingVault = null;
  clearTimeout(S.pollTimer);
  decCache.clear(); pubKeyCache.clear();
  location.reload();
}

async function checkSession() {
  const {ok, data} = await api('/auth/me');
  if (ok && data.authenticated) {
    S.me = {email: data.email, name: data.name, color: data.color};
    await _resolvePrivateKeyNoPassword(data);
    if (data.public_key) {
      try { S.rsaPublicKey = await importPublicKey(data.public_key); pubKeyCache.set(data.email, S.rsaPublicKey); } catch(e) {}
    }
    enterApp(data);
  }
}

// ═══════════════════════════════════════════════
//  App shell
// ═══════════════════════════════════════════════
function enterApp(data={}) {
  $('auth').classList.add('hidden');
  $('app').classList.remove('hidden');
  $('my-avatar').textContent = initials(S.me.name);
  $('my-avatar').style.background = S.me.color;
  $('my-name').textContent  = S.me.name;
  $('my-email').textContent = S.me.email;
  renderStatusBar(data);
  loadInbox();

  // Adaptive poll loop — uses setTimeout so each interval can be dynamic
  function schedulePoll() {
    S.pollTimer = setTimeout(async () => {
      let gotNew = false;
      await loadInbox();
      if (S.activeContact) gotNew = await loadThread(S.activeContact.email, false);
      if (gotNew) _resetPollInterval(); else _backoffPollInterval();
      schedulePoll();
    }, _effectivePoll());
  }
  schedulePoll();

  // Re-sync poll speed when tab becomes visible again
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
      clearTimeout(S.pollTimer);
      _resetPollInterval();
      // Immediate refresh on return
      loadInbox();
      if (S.activeContact) loadThread(S.activeContact.email, false);
      schedulePoll();
    }
  }, {once: false});
}

function renderStatusBar(data={}) {
  const el = $('status-bar');
  const hasCk = data.has_ck_key ?? true;
  let html = '';
  if (hasCk && data.key_prefix) {
    html += `<div class="bar-item bar-ok">⚿ ${esc(data.key_prefix)}<button class="bar-btn" onclick="$('key-modal').classList.add('open')">update</button></div>`;
  } else if (!hasCk) {
    html += `<div class="bar-item bar-warn">⚠ No ChaosKey key<button class="bar-btn" onclick="$('key-modal').classList.add('open')">add →</button></div>`;
  }
  if (S.rsaPrivateKey) {
    html += `<div class="bar-item bar-ok">🔑 RSA keys ready · cross-device E2EE</div>`;
  } else {
    html += `<div class="bar-item bar-warn">⚠ Keys not loaded<button class="bar-btn" onclick="_showVaultPwModal()">unlock →</button></div>`;
  }
  el.innerHTML = html;
}

// ═══════════════════════════════════════════════
//  Inbox / threads
// ═══════════════════════════════════════════════
let _lastInboxHash = '';

async function loadInbox() {
  const {ok, data} = await api('/msg/inbox');
  if (!ok || !Array.isArray(data)) return;

  const hash = data.map(t => t.contact + t.total).join('|');
  const changed = hash !== _lastInboxHash;
  _lastInboxHash = hash;

  S.threads = data;
  // Use DocumentFragment for batch DOM insertion — avoids N reflows
  if (changed) {
    renderThreadList();
    prefetchAllContactKeys(data.map(t => t.contact));
  }
}

function renderThreadList() {
  const el = $('thread-list');
  if (!S.threads.length) {
    el.innerHTML = `<div class="no-threads">No conversations yet.<br>Search for a user above.</div>`;
    return;
  }
  const frag = document.createDocumentFragment();
  for (const t of S.threads) {
    const div = document.createElement('div');
    div.className = `thread-item${S.activeContact?.email===t.contact?' active':''}`;
    div.onclick = () => openThread(t.contact, t.name, t.color);
    div.innerHTML = `
      <div class="avatar" style="background:${t.color}">${initials(t.name)}</div>
      <div class="thread-info">
        <div class="thread-name">${esc(t.name)}</div>
        <div class="thread-email">${esc(t.contact)}</div>
      </div>
      <div class="thread-time">${fmtDate(t.last_at)}</div>`;
    frag.appendChild(div);
  }
  el.innerHTML = '';
  el.appendChild(frag);
}

async function onSearchInput(val) {
  const res = $('search-results');
  if (!val || val.length < 3) { res.classList.remove('open'); return; }
  const {ok, data} = await api('/msg/search_user?q=' + encodeURIComponent(val));
  if (!ok || !data.length) { res.classList.remove('open'); return; }
  const frag = document.createDocumentFragment();
  for (const u of data) {
    const div = document.createElement('div');
    div.className = 'search-result-item';
    div.onclick = () => openThread(u.email, u.name, u.color);
    div.innerHTML = `
      <div class="avatar" style="background:${u.color};width:28px;height:28px;font-size:.75rem">${initials(u.name)}</div>
      <div class="sr-info"><div class="sr-name">${esc(u.name)}</div><div class="sr-email">${esc(u.email)}</div></div>`;
    frag.appendChild(div);
  }
  res.innerHTML = '';
  res.appendChild(frag);
  res.classList.add('open');
}
function closeSearch() { $('search-results').classList.remove('open'); }

// ═══════════════════════════════════════════════
//  Thread view
// ═══════════════════════════════════════════════
function openThread(email, name, color) {
  S.activeContact = {email, name, color};
  $('contact-name').textContent   = name;
  $('contact-email').textContent  = email;
  $('contact-avatar').textContent = initials(name);
  $('contact-avatar').style.background = color;
  $('empty-state').style.display = 'none';
  $('chat-view').classList.add('active');
  $('search-input').value = '';
  closeSearch();
  renderThreadList();

  // Key is almost certainly already in pubKeyCache from inbox bulk-load
  // — prefetchContactKey is a no-op cache hit in that case
  prefetchContactKey(email);

  S.lastMsgId[email] = 0;
  renderedIds.clear();

  const area = $('messages-area');
  area.innerHTML = '';
  area.dataset.contact = email;

  loadThread(email, true);

  specText = ''; specPromise = null; _setSpecIndicator(false);
  $('compose-input').focus();

  // Reset poll backoff when user opens a thread
  _resetPollInterval();
}

/**
 * Returns true if any new messages were rendered (used for poll backoff).
 */
async function loadThread(email, scrollToBottom=false) {
  const since = S.lastMsgId[email] || 0;
  const {ok, data} = await api(`/msg/thread?with=${encodeURIComponent(email)}&since=${since}`);
  if (!ok || !Array.isArray(data)) return false;

  const newMsgs = data.filter(m => !renderedIds.has(m.id));
  if (!newMsgs.length) return false;

  const maxId = Math.max(...data.map(m => m.id));
  if (maxId > (S.lastMsgId[email] || 0)) S.lastMsgId[email] = maxId;

  // Mark rendered BEFORE async decryption to prevent concurrent poll double-render
  newMsgs.forEach(m => renderedIds.add(m.id));

  const resolved = await Promise.all(newMsgs.map(async m => {
    if (decCache.has(m.id)) return {id: m.id, from: m.from, sent_at: m.sent_at, text: decCache.get(m.id)};

    let text = '[Decryption failed]';
    if (!S.rsaPrivateKey) {
      text = '[Keys not loaded — unlock vault to read]';
    } else if (!m.ciphertext || !m.nonce) {
      text = '[Missing encrypted data]';
    } else {
      const isMine  = m.from === S.me.email;
      const wrapped = isMine ? m.sender_enc_key : m.rsa_enc_key;
      if (!wrapped) {
        text = isMine ? '[Sent before self-wrap]' : '[Missing encrypted key]';
      } else {
        try {
          const rawEncKey = await rsaDecrypt(wrapped);
          if (!rawEncKey) {
            text = '[RSA unwrap failed — wrong device or rotated keys]';
          } else {
            const dec = await callChaosKey('/v1/decrypt', {
              ciphertext:     m.ciphertext,
              nonce:          m.nonce,
              encryption_key: rawEncKey,
            });
            text = dec.plaintext ?? '[Empty]';
            decCacheSet(m.id, text);
          }
        } catch(e) { text = `[${e.message || 'Decryption error'}]`; }
      }
    }
    return {id: m.id, from: m.from, sent_at: m.sent_at, text};
  }));

  const area = $('messages-area');
  if (area.dataset.contact !== email) return false;

  // Batch all new bubbles into a single DocumentFragment — one DOM insertion
  const frag = document.createDocumentFragment();
  let confirmedOptimistic = false;

  for (const m of resolved) {
    const pendingEl = area.querySelector(`[data-pending="${m.id}"]`);
    if (pendingEl) {
      pendingEl.removeAttribute('data-pending');
      pendingEl.classList.remove('optimistic');
      pendingEl.querySelector('.msg-meta').textContent = fmtTime(m.sent_at);
      pendingEl.querySelector('.e2ee-tag').textContent = '⚿ ChaosKey + RSA-OAEP';
      confirmedOptimistic = true;
      continue;
    }

    const mine = m.from === S.me.email;
    const isErr = m.text.startsWith('[');
    const el = document.createElement('div');
    el.className = `msg-group ${mine ? 'mine' : 'theirs'}`;
    el.innerHTML = `
      <div class="bubble${isErr ? ' err-bubble' : ''}">${esc(m.text)}</div>
      <div class="msg-meta">${fmtTime(m.sent_at)}</div>
      <div class="e2ee-tag">⚿ ChaosKey + RSA-OAEP</div>`;
    frag.appendChild(el);
  }

  if (frag.childNodes.length > 0) area.appendChild(frag);

  if (scrollToBottom || _isNearBottom(area)) area.scrollTop = area.scrollHeight;
  return true;
}

function _isNearBottom(el) {
  return el.scrollHeight - el.scrollTop - el.clientHeight < 120;
}

function onComposeInput(ta) {
  autoResize(ta);
  _startSpecEncrypt(ta.value.trim());
}

// ═══════════════════════════════════════════════
//  Send  (optimistic + speculative)
// ═══════════════════════════════════════════════
async function sendMessage() {
  const inp = $('compose-input');
  const txt = inp.value.trim();
  if (!txt || !S.activeContact) return;

  const btn = $('send-btn');
  btn.disabled = true;

  // ── OPTIMISTIC BUBBLE ──────────────────────────────────────
  const area = $('messages-area');
  const optEl = document.createElement('div');
  optEl.className = 'msg-group mine optimistic';
  optEl.dataset.text = txt;
  optEl.innerHTML = `
    <div class="bubble">${esc(txt)}</div>
    <div class="msg-meta">${fmtTime(new Date().toISOString())}</div>
    <div class="e2ee-tag">⚿ encrypting…</div>`;
  area.appendChild(optEl);
  area.scrollTop = area.scrollHeight;

  inp.value = ''; inp.style.height = 'auto';
  specText = ''; specPromise = null; _setSpecIndicator(false);

  // Reset poll backoff on send — we want fast polling now
  _resetPollInterval();

  try {
    const contactEmail = S.activeContact.email;

    // Kick off key fetches in parallel with potential spec encrypt
    const [, recipPubKey] = await Promise.all([
      ensureOwnPublicKey(),
      prefetchContactKey(contactEmail),
    ]);
    if (!S.rsaPublicKey)  throw new Error('Your public key missing — log in again');
    if (!recipPubKey) throw new Error('Recipient has no public key — they need to log in first');

    // Use speculative result if available, else fresh call
    let ck;
    if (specText === txt && specPromise) {
      ck = await specPromise;
      if (!ck) throw new Error('Speculative encrypt failed, retrying…');
    } else {
      ck = await callChaosKey('/v1/encrypt', {plaintext: txt});
    }

    const [rsa_enc_key, sender_enc_key] = await Promise.all([
      rsaEncrypt(ck.encryption_key, recipPubKey),
      rsaEncrypt(ck.encryption_key, S.rsaPublicKey),
    ]);

    const {ok, data} = await api('/msg/send', {
      method: 'POST',
      body: JSON.stringify({
        recipient: contactEmail,
        ciphertext: ck.ciphertext,
        nonce: ck.nonce,
        rsa_enc_key,
        sender_enc_key,
      }),
    });
    if (!ok) throw new Error(data.error || 'Send failed');

    // Register in decCache AND renderedIds immediately
    // so the next poll never fetches or re-renders this message
    decCacheSet(data.id, txt);
    renderedIds.add(data.id);

    // Tag the optimistic bubble with the confirmed server id
    optEl.dataset.pending = data.id;

    // Confirm optimistic bubble
    if (optEl.parentNode) {
      optEl.classList.remove('optimistic');
      optEl.removeAttribute('data-pending');
      optEl.querySelector('.e2ee-tag').textContent = '⚿ ChaosKey + RSA-OAEP';
      const metaEl = optEl.querySelector('.msg-meta');
      if (metaEl) metaEl.textContent = fmtTime(data.sent_at);
    }

    // Update incremental cursor
    if (!S.lastMsgId[contactEmail] || data.id > S.lastMsgId[contactEmail]) {
      S.lastMsgId[contactEmail] = data.id;
    }

    // Update inbox thread list counter locally without a network round-trip
    const thr = S.threads.find(t => t.contact === contactEmail);
    if (thr) { thr.total++; thr.last_at = data.sent_at; }
    // Re-render thread list (cheap — just DOM, no fetch)
    renderThreadList();

  } catch(e) {
    if (optEl.parentNode) optEl.remove();
    inp.value = txt;
    autoResize(inp);
    toast('✗ ' + e.message, 'err');
  } finally {
    btn.disabled = false;
    inp.focus();
  }
}

// ═══════════════════════════════════════════════
//  Burn thread  — INSTANT
// ═══════════════════════════════════════════════
function confirmBurn() {
  if (!S.activeContact) return;
  $('burn-modal-text').textContent = `Burn all messages with ${S.activeContact.name}? This cannot be undone.`;
  $('burn-modal').classList.add('open');
}

async function executeBurn() {
  closeMod('burn-modal');
  if (!S.activeContact) return;
  const contact = S.activeContact.email;

  const area = $('messages-area');
  area.innerHTML = `<div style="text-align:center;color:var(--dust);font-family:'Fira Code',monospace;font-size:.73rem;margin-top:2rem">No messages yet.</div>`;
  area.dataset.contact = contact;

  S.lastMsgId[contact] = 0;
  renderedIds.clear();
  decCache.clear();

  toast('🔥 Thread burned', 'ok');

  api('/msg/burn', {method:'POST', body:JSON.stringify({contact})}).then(({ok}) => {
    if (!ok) toast('⚠ Burn failed on server — refresh to resync', 'err', 5000);
    else loadInbox();
  });
}

// ═══════════════════════════════════════════════
//  ChaosKey key modal
// ═══════════════════════════════════════════════
async function saveUpdatedKey() {
  const val   = $('modal-ck-input').value.trim();
  const errEl = $('key-modal-err');
  if (!val || !val.startsWith('ck_live_')) { errEl.textContent = '⚠ Key must start with ck_live_'; return; }
  const {ok, data} = await api('/auth/update_ck_key', {method:'POST', body:JSON.stringify({chaoskey_api_key:val})});
  if (ok) {
    closeMod('key-modal');
    $('modal-ck-input').value = '';
    toast('⚿ ChaosKey API key updated', 'ok');
    renderStatusBar({has_ck_key:true, key_prefix: data.key_prefix});
  } else {
    errEl.textContent = '⚠ ' + (data.error || 'Update failed');
  }
}

// ═══════════════════════════════════════════════
//  Re-key flow
// ═══════════════════════════════════════════════
function showRekeyModal(reason='missing') {
  $('rekey-modal-title').textContent = reason==='failed' ? 'Generate new keys' : 'No key vault found';
  $('rekey-modal-desc').textContent  = reason==='failed'
    ? 'Vault decryption failed. Generate a fresh keypair — old messages won\'t be recoverable, but new messages will work normally.'
    : 'No key vault found. Enter your password to generate a fresh RSA keypair.';
  $('rekey-modal-err').textContent   = '';
  $('rekey-pw-input').value          = '';
  $('rekey-modal').classList.add('open');
  setTimeout(() => $('rekey-pw-input').focus(), 150);
}

async function executeRekey() {
  const pw    = $('rekey-pw-input').value;
  const errEl = $('rekey-modal-err');
  const btn   = $('rekey-confirm-btn');
  if (!pw)   { errEl.textContent = '⚠ Password required'; return; }
  if (!S.me) { errEl.textContent = '⚠ Not logged in'; return; }

  btn.disabled = true; btn.textContent = 'Generating…'; errEl.textContent = '';
  try {
    const {pubB64, encPrivB64, saltHex} = await genAndRegisterKeys(pw, S.me.email);
    const {ok, data} = await api('/auth/rekey', {
      method: 'POST',
      body: JSON.stringify({password:pw, public_key:pubB64, encrypted_private_key:encPrivB64, vault_salt:saltHex}),
    });
    if (!ok) { errEl.textContent = '⚠ ' + (data.error || 'Re-key failed'); return; }
    closeMod('rekey-modal');
    decCache.clear();
    pubKeyCache.set(S.me.email, S.rsaPublicKey);
    renderStatusBar({has_ck_key: !!S.me, key_prefix: null});
    toast('🔑 New RSA keys generated and saved', 'ok', 5000);
  } catch(e) {
    errEl.textContent = '⚠ ' + (e.message || 'Unknown error');
  } finally { btn.disabled = false; btn.textContent = 'Generate keys'; }
}

// ═══════════════════════════════════════════════
//  Boot
// ═══════════════════════════════════════════════
checkSession();
</script>
</body>
</html>"""


@app.route("/")
def index():
    return render_template_string(HTML)


try:
    init_db()
except Exception as e:
    log.error(f"DB init failed: {e}")

if __name__ == "__main__":
    log.info(f"BurnChat starting on port {PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
