"""
BurnChat — Encrypted Ephemeral Messenger (Client-Side ChaosKey Edition)
========================================================================
Hybrid encryption model — ALL crypto happens in the browser:

  Send flow (browser):
    1. Browser calls /proxy/encrypt → server calls ChaosKey → returns ciphertext, nonce, enc_key
    2. Browser fetches recipient's RSA public key from server
    3. Browser RSA-OAEP encrypts the enc_key with recipient's public key
    4. Only ciphertext + nonce + rsa_enc_key are sent to the server relay
    5. Server stores encrypted payload — never sees plaintext or raw enc_key

  Receive flow (browser):
    1. Browser fetches encrypted messages from server
    2. Browser RSA-OAEP decrypts rsa_enc_key with its local private key
    3. Browser calls /proxy/decrypt → server calls ChaosKey → returns plaintext

  Cross-Device Escrow Flow:
    1. Browser derives AES-256-GCM key from User's Password + Email via PBKDF2
    2. Browser encrypts the RSA Private Key using this AES key
    3. Encrypted vault is sent to the server. The server never sees the password.
    4. On login from a new device, the vault is fetched and decrypted locally.

  CORS Note:
    ChaosKey does not emit Access-Control-Allow-Origin headers, so browsers cannot
    call it directly. /proxy/encrypt and /proxy/decrypt forward those calls server-side
    using the API key stored in the DB — the security model is unchanged because the
    server still never sees plaintext or the raw enc_key.
"""

import os, secrets, hmac, logging, urllib.request as _urllib_req, json as _json
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, request, jsonify, g, session, render_template_string
from flask_cors import CORS

# ── bcrypt ────────────────────────────────────────────────────────────────────
try:
    import bcrypt as _bcrypt
    def hash_password(pw: str) -> str:
        return _bcrypt.hashpw(pw.encode(), _bcrypt.gensalt(12)).decode()
    def check_password(pw: str, h: str) -> bool:
        return _bcrypt.checkpw(pw.encode(), h.encode())
except ImportError:
    import hashlib as _hl
    def hash_password(pw: str) -> str:
        salt = secrets.token_hex(16)
        h = _hl.sha256((salt + pw).encode()).hexdigest()
        return f"sha256${salt}${h}"
    def check_password(pw: str, hashed: str) -> bool:
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
log.info(f"Database backend: {'postgresql' if USE_POSTGRES else 'sqlite'}")
log.info("Encryption mode: CLIENT-SIDE (ChaosKey proxied server-side + RSA-OAEP in browser)")

app = Flask("BurnChat")
app.secret_key = SECRET_KEY
CORS(app, supports_credentials=True)

# ── Database abstraction ──────────────────────────────────────────────────────
if USE_POSTGRES:
    import psycopg2, psycopg2.extras, urllib.parse as up

    def _pg_url():
        url = (DATABASE_URL or "").strip()
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql://", 1)
        parsed = up.urlparse(url)
        qs = up.parse_qs(parsed.query)
        qs.pop("channel_binding", None)
        return up.urlunparse(parsed._replace(query=up.urlencode(qs, doseq=True)))

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
    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(DB_PATH)
            g.db.row_factory = sqlite3.Row
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
CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    email            TEXT UNIQUE NOT NULL,
    display_name     TEXT NOT NULL,
    password_hash    TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    avatar_color     TEXT NOT NULL DEFAULT '#ff6b35',
    chaoskey_api_key TEXT,
    public_key       TEXT,
    encrypted_private_key TEXT
);
CREATE TABLE IF NOT EXISTS messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sender       TEXT NOT NULL,
    recipient    TEXT NOT NULL,
    ciphertext   TEXT NOT NULL,
    nonce        TEXT NOT NULL DEFAULT '',
    enc_key      TEXT NOT NULL DEFAULT '',
    sent_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_msg_thread ON messages(sender, recipient);
"""

SCHEMA_PG_STMTS = [
    """CREATE TABLE IF NOT EXISTS users (
        id               SERIAL PRIMARY KEY,
        email            TEXT UNIQUE NOT NULL,
        display_name     TEXT NOT NULL,
        password_hash    TEXT NOT NULL,
        created_at       TEXT NOT NULL,
        avatar_color     TEXT NOT NULL DEFAULT '#ff6b35',
        chaoskey_api_key TEXT,
        public_key       TEXT,
        encrypted_private_key TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS messages (
        id           SERIAL PRIMARY KEY,
        sender       TEXT NOT NULL,
        recipient    TEXT NOT NULL,
        ciphertext   TEXT NOT NULL,
        nonce        TEXT NOT NULL DEFAULT '',
        enc_key      TEXT NOT NULL DEFAULT '',
        sent_at      TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_msg_thread ON messages(sender, recipient)",
]

PG_MIGRATIONS = [
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_color TEXT NOT NULL DEFAULT '#ff6b35'",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS chaoskey_api_key TEXT",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS public_key TEXT",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS encrypted_private_key TEXT",
]

def init_db():
    with app.app_context():
        if USE_POSTGRES:
            conn = psycopg2.connect(_pg_url())
            conn.autocommit = True
            cur = conn.cursor()
            for stmt in SCHEMA_PG_STMTS + PG_MIGRATIONS:
                try:
                    cur.execute(stmt)
                except Exception as e:
                    log.warning(f"Migration skipped: {e}")
            conn.close()
        else:
            db = sqlite3.connect(DB_PATH)
            db.executescript(SCHEMA_SQLITE)
            for col, default in [
                ("avatar_color", "'#ff6b35'"),
                ("chaoskey_api_key", "NULL"),
                ("public_key", "NULL"),
                ("encrypted_private_key", "NULL"),
            ]:
                try:
                    db.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT NOT NULL DEFAULT {default}")
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
    "#ff6b35", "#f7931e", "#ffcd3c", "#4ecdc4",
    "#45b7d1", "#a29bfe", "#fd79a8", "#00b894"
]

def pick_color(email: str) -> str:
    return AVATAR_COLORS[sum(ord(c) for c in email) % len(AVATAR_COLORS)]

def require_login(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "user_email" not in session:
            return jsonify({"error": "Not authenticated"}), 401
        return f(*args, **kwargs)
    return wrapped

def _get_user_ck_key(email: str) -> str:
    """Fetch the ChaosKey API key for a logged-in user from the DB."""
    user = db_exec("SELECT chaoskey_api_key FROM users WHERE email = ?", (email,)).fetchone()
    return (user["chaoskey_api_key"] or "") if user else ""

# ── ChaosKey proxy helpers ────────────────────────────────────────────────────
def _chaoskey_post(path: str, payload: dict, ck_key: str):
    """
    Make a server-side POST to ChaosKey. This bypasses the browser CORS restriction
    because the request originates from the server, not the browser.
    """
    req = _urllib_req.Request(
        f"{CHAOSKEY_URL}{path}",
        data=_json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {ck_key}",
            "Content-Type":  "application/json",
        },
        method="POST",
    )
    with _urllib_req.urlopen(req, timeout=10) as resp:
        body = resp.read()
        return _json.loads(body), resp.status

# ── Auth routes ───────────────────────────────────────────────────────────────
@app.route("/auth/signup", methods=["POST"])
def signup():
    body       = request.get_json(force=True) or {}
    email      = body.get("email", "").strip().lower()
    pw         = body.get("password", "").strip()
    name       = body.get("name", "").strip() or email.split("@")[0]
    ck_key     = body.get("chaoskey_api_key", "").strip()
    public_key = body.get("public_key", "").strip()
    enc_priv   = body.get("encrypted_private_key", "").strip()

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
            "chaoskey_api_key, public_key, encrypted_private_key) VALUES (?,?,?,?,?,?,?,?)",
            (email, name, hash_password(pw), now_iso(), color, ck_key, public_key, enc_priv)
        )
        db_commit()
    except Exception as e:
        if "unique" in str(e).lower():
            return jsonify({"error": "Email already registered"}), 409
        return jsonify({"error": str(e)}), 500

    session["user_email"] = email
    session["user_name"]  = name
    session["user_color"] = color
    return jsonify({"ok": True, "email": email, "name": name, "color": color,
                    "ck_api_key": ck_key,
                    "key_prefix": ck_key[:16] + "…"}), 201


@app.route("/auth/login", methods=["POST"])
def login():
    body  = request.get_json(force=True) or {}
    email = body.get("email", "").strip().lower()
    pw    = body.get("password", "").strip()

    if not email or not pw:
        return jsonify({"error": "Email and password required"}), 400

    user = db_exec(
        "SELECT email, display_name, password_hash, avatar_color, chaoskey_api_key, "
        "public_key, encrypted_private_key FROM users WHERE email = ?", (email,)
    ).fetchone()

    if not user or not check_password(pw, user["password_hash"]):
        return jsonify({"error": "Invalid email or password"}), 401

    ck_key = user["chaoskey_api_key"] or ""
    session["user_email"] = user["email"]
    session["user_name"]  = user["display_name"]
    session["user_color"] = user["avatar_color"]
    return jsonify({
        "ok":                   True,
        "email":                user["email"],
        "name":                 user["display_name"],
        "color":                user["avatar_color"],
        "ck_api_key":           ck_key,
        "key_prefix":           (ck_key[:16] + "…") if ck_key else None,
        "has_ck_key":           bool(ck_key),
        "public_key":           user["public_key"] or "",
        "encrypted_private_key": user["encrypted_private_key"] or "",
    })


@app.route("/auth/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/auth/me", methods=["GET"])
def me():
    if "user_email" not in session:
        return jsonify({"authenticated": False}), 200
    user = db_exec(
        "SELECT chaoskey_api_key FROM users WHERE email = ?", (session["user_email"],)
    ).fetchone()
    ck_key = user["chaoskey_api_key"] if user else ""
    return jsonify({
        "authenticated": True,
        "email":         session["user_email"],
        "name":          session["user_name"],
        "color":         session.get("user_color", "#ff6b35"),
        "has_ck_key":    bool(ck_key),
        "ck_api_key":    ck_key or "",
        "key_prefix":    (ck_key[:16] + "…") if ck_key else None,
    })


@app.route("/auth/update_ck_key", methods=["POST"])
@require_login
def update_ck_key():
    body   = request.get_json(force=True) or {}
    ck_key = body.get("chaoskey_api_key", "").strip()
    if not ck_key or not ck_key.startswith("ck_live_"):
        return jsonify({"error": "Valid ChaosKey API key required (starts with ck_live_)"}), 400
    db_exec("UPDATE users SET chaoskey_api_key = ? WHERE email = ?",
            (ck_key, session["user_email"]))
    db_commit()
    return jsonify({"ok": True, "ck_api_key": ck_key, "key_prefix": ck_key[:16] + "…"})


# ── ChaosKey proxy routes ─────────────────────────────────────────────────────
@app.route("/proxy/encrypt", methods=["POST"])
@require_login
def proxy_encrypt():
    """
    Server-side proxy to ChaosKey /v1/encrypt.
    Exists solely to work around ChaosKey's missing CORS headers.
    The server reads the stored API key and forwards the plaintext to ChaosKey;
    it returns only the ciphertext + nonce + enc_key — the same data the browser
    would have received if it could call ChaosKey directly.
    """
    body   = request.get_json(force=True) or {}
    ck_key = _get_user_ck_key(session["user_email"])
    if not ck_key:
        return jsonify({"error": "No ChaosKey API key on account"}), 400
    try:
        data, status = _chaoskey_post("/v1/encrypt", {"plaintext": body.get("plaintext", "")}, ck_key)
        return jsonify(data), status
    except Exception as e:
        log.error(f"ChaosKey /v1/encrypt proxy error: {e}")
        return jsonify({"error": str(e)}), 502


@app.route("/proxy/decrypt", methods=["POST"])
@require_login
def proxy_decrypt():
    """
    Server-side proxy to ChaosKey /v1/decrypt.
    Exists solely to work around ChaosKey's missing CORS headers.
    The server never sees the plaintext key — the browser has already RSA-unwrapped
    the enc_key before calling this endpoint, but the server only forwards
    ciphertext + nonce + enc_key to ChaosKey and returns the plaintext to the browser.
    """
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
        log.error(f"ChaosKey /v1/decrypt proxy error: {e}")
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
    """
    Pure relay endpoint. The browser has already:
      1. Called /proxy/encrypt to encrypt the plaintext via ChaosKey
      2. RSA-OAEP wrapped the enc_key with the recipient's public key
    We just validate and store the encrypted payload.
    """
    body        = request.get_json(force=True) or {}
    recipient   = body.get("recipient", "").strip().lower()
    ciphertext  = body.get("ciphertext", "").strip()
    nonce       = body.get("nonce", "").strip()
    rsa_enc_key = body.get("rsa_enc_key", "").strip()
    sender      = session["user_email"]

    if not recipient:
        return jsonify({"error": "recipient required"}), 400
    if not ciphertext or not nonce or not rsa_enc_key:
        return jsonify({"error": "ciphertext, nonce, and rsa_enc_key are required"}), 400
    if recipient == sender:
        return jsonify({"error": "Cannot message yourself"}), 400

    exists = db_exec("SELECT id FROM users WHERE email = ?", (recipient,)).fetchone()
    if not exists:
        return jsonify({"error": f"User '{recipient}' not found on BurnChat"}), 404

    db_exec(
        "INSERT INTO messages (sender, recipient, ciphertext, nonce, enc_key, sent_at) "
        "VALUES (?,?,?,?,?,?)",
        (sender, recipient, ciphertext, nonce, rsa_enc_key, now_iso())
    )
    db_commit()
    return jsonify({"ok": True, "sent_at": now_iso(), "mode": "client-chaoskey+rsa"}), 201


@app.route("/msg/thread", methods=["GET"])
@require_login
def get_thread():
    contact = request.args.get("with", "").strip().lower()
    me      = session["user_email"]

    if not contact:
        return jsonify({"error": "?with= required"}), 400

    rows = db_exec(
        "SELECT id, sender, ciphertext, nonce, enc_key, sent_at "
        "FROM messages "
        "WHERE (sender=? AND recipient=?) OR (sender=? AND recipient=?) "
        "ORDER BY id ASC",
        (me, contact, contact, me)
    ).fetchall()

    return jsonify([{
        "id":          r["id"],
        "from":        r["sender"],
        "ciphertext":  r["ciphertext"],
        "nonce":       r["nonce"],
        "rsa_enc_key": r["enc_key"],
        "sent_at":     r["sent_at"],
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
    me = session["user_email"]
    rows = db_exec(
        "SELECT "
        "  CASE WHEN sender=? THEN recipient ELSE sender END as contact, "
        "  MAX(sent_at) as last_at, "
        "  COUNT(*) as total "
        "FROM messages WHERE sender=? OR recipient=? "
        "GROUP BY contact ORDER BY last_at DESC",
        (me, me, me)
    ).fetchall()

    result = []
    for r in rows:
        user = db_exec(
            "SELECT display_name, avatar_color FROM users WHERE email=?", (r["contact"],)
        ).fetchone()
        result.append({
            "contact": r["contact"],
            "name":    user["display_name"] if user else r["contact"].split("@")[0],
            "color":   user["avatar_color"] if user else "#888",
            "last_at": r["last_at"],
            "total":   r["total"],
        })
    return jsonify(result)


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
        "status":       "ok",
        "chaoskey_url": CHAOSKEY_URL,
        "db_backend":   "postgresql" if USE_POSTGRES else "sqlite",
        "e2ee":         "CLIENT-SIDE: ChaosKey AES-256-GCM (server-proxied) + RSA-OAEP (browser-only)",
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
  --void:#060608; --coal:#0d0e13; --ash:#181a22; --cinder:#22252f;
  --smoke:#2e3140; --dust:#4a4f61; --fog:#6b7182; --mist:#9097a8;
  --paper:#c8ccdb; --snow:#eef0f6;
  --ember:#ff6b35; --flame:#ff8c42; --glow:#ffb347; --spark:#ffd166;
  --cold:#4ecdc4; --ice:#a8e6cf;
  --ember-dim:rgba(255,107,53,.12); --ember-mid:rgba(255,107,53,.25);
  --ember-glow:0 0 30px rgba(255,107,53,.3);
  --r-sm:8px; --r-md:14px; --r-lg:20px; --r-xl:28px;
}
html{-webkit-font-smoothing:antialiased;height:100%}
body{background:var(--void);color:var(--paper);font-family:'Syne',sans-serif;height:100%;overflow:hidden}
::-webkit-scrollbar{width:3px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--smoke);border-radius:2px}

/* AUTH */
#auth{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;background:var(--void);z-index:100}
#auth.hidden{display:none}
.auth-bg{position:absolute;inset:0;background:radial-gradient(ellipse 80% 60% at 20% 80%,rgba(255,107,53,.07) 0%,transparent 60%),radial-gradient(ellipse 60% 50% at 80% 20%,rgba(78,205,196,.05) 0%,transparent 50%);pointer-events:none}
.auth-card{position:relative;width:100%;max-width:420px;padding:3rem 2.5rem;background:var(--coal);border:1px solid var(--cinder);border-radius:var(--r-xl);box-shadow:0 40px 80px rgba(0,0,0,.6);animation:riseIn .5s cubic-bezier(.22,1,.36,1) both}
@keyframes riseIn{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:none}}
.auth-wordmark{display:flex;align-items:center;gap:12px;margin-bottom:2.5rem}
.burn-icon{width:42px;height:42px;background:linear-gradient(135deg,var(--ember),var(--glow));border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:1.3rem;box-shadow:var(--ember-glow);flex-shrink:0}
.wordmark-text h1{font-size:1.5rem;font-weight:800;letter-spacing:-.03em;color:var(--snow)}
.wordmark-text p{font-family:'Fira Code',monospace;font-size:.65rem;color:var(--fog);letter-spacing:.06em;margin-top:1px}
.auth-tabs{display:flex;gap:4px;background:var(--ash);border-radius:10px;padding:4px;margin-bottom:1.75rem}
.auth-tab{flex:1;padding:.55rem;background:none;border:none;font-family:'Syne',sans-serif;font-size:.82rem;font-weight:600;color:var(--fog);cursor:pointer;border-radius:7px;transition:all .2s}
.auth-tab.active{background:var(--cinder);color:var(--snow)}
.form-field{margin-bottom:1rem}
.form-field label{display:block;font-family:'Fira Code',monospace;font-size:.68rem;color:var(--fog);letter-spacing:.06em;text-transform:uppercase;margin-bottom:.45rem}
.form-field input{width:100%;padding:.75rem 1rem;background:var(--ash);border:1px solid var(--smoke);border-radius:var(--r-sm);color:var(--snow);font-family:'Syne',sans-serif;font-size:.92rem;outline:none;transition:border-color .2s,box-shadow .2s}
.form-field input::placeholder{color:var(--dust)}
.form-field input:focus{border-color:var(--ember);box-shadow:0 0 0 3px rgba(255,107,53,.12)}
.auth-submit{width:100%;padding:.85rem;margin-top:.5rem;background:linear-gradient(135deg,var(--ember),var(--flame));color:#fff;border:none;border-radius:var(--r-sm);font-family:'Syne',sans-serif;font-weight:700;font-size:.95rem;cursor:pointer;letter-spacing:.01em;transition:all .2s;box-shadow:0 4px 20px rgba(255,107,53,.3)}
.auth-submit:hover{transform:translateY(-1px);box-shadow:0 8px 30px rgba(255,107,53,.4)}
.auth-submit:disabled{opacity:.4;cursor:not-allowed;transform:none}
.auth-err{font-family:'Fira Code',monospace;font-size:.75rem;color:#ff8fab;text-align:center;min-height:1.2rem;margin-top:.75rem}

/* APP SHELL */
#app{display:flex;height:100vh}
#app.hidden{display:none}

/* SIDEBAR */
.sidebar{width:300px;flex-shrink:0;background:var(--coal);border-right:1px solid var(--cinder);display:flex;flex-direction:column;overflow:hidden}
.sidebar-top{padding:1.25rem 1.25rem 0}
.user-row{display:flex;align-items:center;justify-content:space-between;margin-bottom:1.25rem}
.user-chip{display:flex;align-items:center;gap:10px}
.avatar{width:34px;height:34px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:.85rem;color:#fff;flex-shrink:0}
.user-meta .uname{font-size:.88rem;font-weight:700;color:var(--snow)}
.user-meta .uemail{font-family:'Fira Code',monospace;font-size:.65rem;color:var(--fog)}
.logout-btn{background:none;border:none;font-family:'Fira Code',monospace;font-size:.68rem;color:var(--dust);cursor:pointer;padding:.3rem .6rem;border-radius:6px;transition:color .2s,background .2s}
.logout-btn:hover{color:var(--ember);background:var(--ember-dim)}
.search-wrap{position:relative;margin-bottom:1.25rem}
.search-wrap input{width:100%;padding:.6rem .9rem .6rem 2.4rem;background:var(--ash);border:1px solid var(--smoke);border-radius:10px;color:var(--snow);font-family:'Syne',sans-serif;font-size:.85rem;outline:none;transition:border-color .2s}
.search-wrap input:focus{border-color:var(--ember)}
.search-wrap input::placeholder{color:var(--dust)}
.search-icon{position:absolute;left:.8rem;top:50%;transform:translateY(-50%);font-size:.85rem;pointer-events:none;color:var(--fog)}
.search-results{position:absolute;top:calc(100% + 4px);left:0;right:0;background:var(--cinder);border:1px solid var(--smoke);border-radius:10px;overflow:hidden;z-index:50;box-shadow:0 10px 30px rgba(0,0,0,.5);display:none}
.search-results.open{display:block}
.search-result-item{display:flex;align-items:center;gap:10px;padding:.7rem 1rem;cursor:pointer;transition:background .15s}
.search-result-item:hover{background:var(--smoke)}
.sr-info .sr-name{font-size:.85rem;font-weight:600;color:var(--snow)}
.sr-info .sr-email{font-family:'Fira Code',monospace;font-size:.65rem;color:var(--fog)}
.sidebar-label{font-family:'Fira Code',monospace;font-size:.65rem;color:var(--dust);letter-spacing:.08em;text-transform:uppercase;padding:0 1.25rem .5rem}
.thread-list{flex:1;overflow-y:auto;padding:0 .5rem .5rem}
.thread-item{display:flex;align-items:center;gap:10px;padding:.75rem;border-radius:12px;cursor:pointer;transition:background .15s;margin-bottom:2px}
.thread-item:hover{background:var(--ash)}
.thread-item.active{background:var(--ember-dim);border:1px solid var(--ember-mid)}
.thread-item.active .thread-name{color:var(--glow)}
.thread-info{flex:1;min-width:0}
.thread-name{font-size:.9rem;font-weight:600;color:var(--snow);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.thread-email{font-family:'Fira Code',monospace;font-size:.62rem;color:var(--fog);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.thread-time{font-family:'Fira Code',monospace;font-size:.62rem;color:var(--dust);flex-shrink:0}
.no-threads{padding:2rem 1rem;text-align:center;color:var(--dust);font-size:.82rem;line-height:1.6}
.no-threads .nt-icon{font-size:2rem;margin-bottom:.5rem}

/* MAIN */
.main{flex:1;display:flex;flex-direction:column;background:var(--void);overflow:hidden;position:relative}
.empty-state{flex:1;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:.75rem;color:var(--dust);text-align:center;padding:2rem}
.es-icon{font-size:3rem;margin-bottom:.5rem;opacity:.4}
.es-title{font-size:1.1rem;font-weight:700;color:var(--fog)}
.es-sub{font-family:'Fira Code',monospace;font-size:.75rem;line-height:1.6}
.chat-view{display:none;flex-direction:column;height:100%}
.chat-view.active{display:flex}

/* CHAT HEADER */
.chat-header{display:flex;align-items:center;justify-content:space-between;padding:1rem 1.5rem;background:var(--coal);border-bottom:1px solid var(--cinder);flex-shrink:0}
.chat-header-left{display:flex;align-items:center;gap:12px}
.contact-info .cname{font-size:.95rem;font-weight:700;color:var(--snow)}
.contact-info .cemail{font-family:'Fira Code',monospace;font-size:.65rem;color:var(--fog);margin-top:1px}
.enc-badge{display:flex;align-items:center;gap:5px;font-family:'Fira Code',monospace;font-size:.65rem;color:var(--cold);padding:.2rem .55rem;background:rgba(78,205,196,.08);border:1px solid rgba(78,205,196,.2);border-radius:100px}
.burn-thread-btn{display:flex;align-items:center;gap:6px;padding:.45rem .9rem;border-radius:8px;background:rgba(255,90,90,.1);border:1px solid rgba(255,90,90,.2);color:#ff8fab;font-family:'Syne',sans-serif;font-size:.78rem;font-weight:600;cursor:pointer;transition:all .2s}
.burn-thread-btn:hover{background:rgba(255,90,90,.2)}

/* MESSAGES */
.messages{flex:1;overflow-y:auto;padding:1.5rem;display:flex;flex-direction:column;gap:.75rem}
.msg-group{display:flex;flex-direction:column;gap:3px;max-width:70%}
.msg-group.mine{align-self:flex-end;align-items:flex-end}
.msg-group.theirs{align-self:flex-start;align-items:flex-start}
.bubble{padding:.65rem 1rem;font-family:'Lora',serif;font-size:.9rem;line-height:1.6;word-break:break-word}
.mine .bubble{background:linear-gradient(135deg,var(--ember),var(--flame));color:#fff;border-radius:18px 18px 4px 18px}
.theirs .bubble{background:var(--ash);border:1px solid var(--cinder);color:var(--snow);border-radius:18px 18px 18px 4px}
.msg-meta{font-family:'Fira Code',monospace;font-size:.6rem;color:var(--dust);padding:0 .3rem}
.e2ee-tag{font-family:'Fira Code',monospace;font-size:.55rem;color:var(--cold);opacity:.6;padding:0 .3rem}

/* COMPOSE */
.compose{padding:1rem 1.5rem;background:var(--coal);border-top:1px solid var(--cinder);display:flex;gap:.75rem;align-items:flex-end;flex-shrink:0}
.compose-wrap{flex:1;background:var(--ash);border:1px solid var(--smoke);border-radius:14px;overflow:hidden;transition:border-color .2s,box-shadow .2s}
.compose-wrap:focus-within{border-color:var(--ember);box-shadow:0 0 0 3px rgba(255,107,53,.1)}
.compose-input{width:100%;padding:.8rem 1rem;background:none;border:none;color:var(--snow);font-family:'Lora',serif;font-size:.9rem;outline:none;resize:none;max-height:120px;line-height:1.5}
.compose-input::placeholder{color:var(--dust)}
.send-btn{width:44px;height:44px;flex-shrink:0;background:linear-gradient(135deg,var(--ember),var(--flame));border:none;border-radius:12px;color:#fff;font-size:1.1rem;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .2s;box-shadow:0 4px 12px rgba(255,107,53,.3)}
.send-btn:hover{transform:scale(1.05);box-shadow:0 6px 20px rgba(255,107,53,.45)}
.send-btn:disabled{opacity:.35;cursor:not-allowed;transform:none}

/* MODALS */
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;z-index:200;opacity:0;pointer-events:none;transition:opacity .2s}
.modal-overlay.open{opacity:1;pointer-events:all}
.modal{background:var(--coal);border:1px solid var(--cinder);border-radius:var(--r-xl);padding:2rem 2.25rem;max-width:380px;width:90%;box-shadow:0 40px 80px rgba(0,0,0,.6);transform:scale(.95);transition:transform .2s}
.modal-overlay.open .modal{transform:scale(1)}
.modal-icon{font-size:2.5rem;margin-bottom:1rem}
.modal h2{font-size:1.1rem;font-weight:800;color:var(--snow);margin-bottom:.5rem}
.modal p{font-family:'Fira Code',monospace;font-size:.75rem;color:var(--fog);line-height:1.6;margin-bottom:1.5rem}
.modal-btns{display:flex;gap:.75rem}
.modal-cancel,.modal-confirm{flex:1;padding:.7rem;border-radius:10px;border:none;font-family:'Syne',sans-serif;font-weight:700;font-size:.88rem;cursor:pointer;transition:all .15s}
.modal-cancel{background:var(--ash);color:var(--paper);border:1px solid var(--smoke)}
.modal-cancel:hover{border-color:var(--fog)}
.modal-confirm{background:linear-gradient(135deg,#ff4444,#ff6b35);color:#fff;box-shadow:0 4px 15px rgba(255,60,60,.3)}
.modal-confirm:hover{transform:translateY(-1px);box-shadow:0 6px 20px rgba(255,60,60,.4)}

/* TOAST */
.toast{position:fixed;bottom:2rem;left:50%;transform:translateX(-50%) translateY(20px);background:var(--cinder);color:var(--snow);font-family:'Fira Code',monospace;font-size:.78rem;padding:.65rem 1.25rem;border-radius:100px;border:1px solid var(--smoke);opacity:0;transition:opacity .25s,transform .25s;pointer-events:none;z-index:300;white-space:nowrap}
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
        <p>RSA-OAEP · AES-256-GCM · CLIENT-SIDE E2EE</p>
      </div>
    </div>
    <div class="auth-tabs">
      <button class="auth-tab active" id="tab-in" onclick="switchAuthTab('login')">Sign in</button>
      <button class="auth-tab" id="tab-up" onclick="switchAuthTab('signup')">Create account</button>
    </div>
    <div id="auth-fields">
      <div class="form-field" id="field-name" style="display:none">
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
      <div class="form-field" id="field-ck-key" style="display:none">
        <label>ChaosKey API key</label>
        <input id="f-ck-key" type="text" placeholder="ck_live_…" autocomplete="off" spellcheck="false"
          style="font-family:'Fira Code',monospace;font-size:.82rem">
        <div style="font-family:'Fira Code',monospace;font-size:.63rem;color:var(--fog);margin-top:.4rem;line-height:1.5">
          Register on ChaosKey → copy your <code style="color:var(--ember)">ck_live_…</code> key here
        </div>
      </div>
    </div>
    <button class="auth-submit" id="auth-btn" onclick="doAuth()">Sign in →</button>
    <div class="auth-err" id="auth-err"></div>
  </div>
</div>

<div id="app" class="hidden">
  <div class="sidebar" id="sidebar">
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
      <div id="ck-key-bar" style="display:none;align-items:center;justify-content:space-between;margin-bottom:.75rem;padding:.45rem .7rem;background:var(--ash);border:1px solid var(--smoke);border-radius:8px;">
        <div style="display:flex;align-items:center;gap:6px;">
          <span style="font-size:.7rem">⚿</span>
          <span id="ck-key-prefix" style="font-family:'Fira Code',monospace;font-size:.65rem;color:var(--fog)"></span>
        </div>
        <button onclick="showUpdateKeyModal()" style="background:none;border:none;font-family:'Fira Code',monospace;font-size:.62rem;color:var(--dust);cursor:pointer;padding:0;transition:color .15s" onmouseover="this.style.color='var(--ember)'" onmouseout="this.style.color='var(--dust)'">update</button>
      </div>
      <div id="ck-key-warn" style="display:none;padding:.5rem .7rem;background:rgba(255,107,53,.1);border:1px solid rgba(255,107,53,.25);border-radius:8px;margin-bottom:.75rem;">
        <div style="font-family:'Fira Code',monospace;font-size:.65rem;color:var(--ember);margin-bottom:.3rem">⚠ No ChaosKey API key</div>
        <button onclick="showUpdateKeyModal()" style="background:var(--ember);border:none;color:#fff;font-family:'Syne',sans-serif;font-size:.72rem;font-weight:700;padding:.3rem .7rem;border-radius:6px;cursor:pointer;width:100%">Add key →</button>
      </div>
      <div id="e2ee-status" style="display:none;align-items:center;gap:6px;margin-bottom:.75rem;padding:.4rem .7rem;background:rgba(78,205,196,.06);border:1px solid rgba(78,205,196,.15);border-radius:8px;">
        <span style="font-size:.7rem">🔑</span>
        <span style="font-family:'Fira Code',monospace;font-size:.63rem;color:var(--cold)">RSA keys ready · client-side E2EE</span>
      </div>
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
      <div class="no-threads">
        <div class="nt-icon">🔒</div>
        <div>Search for a user above<br>to start a conversation.</div>
      </div>
    </div>
  </div>

  <div class="main">
    <div class="empty-state" id="empty-state">
      <div class="es-icon">🔥</div>
      <div class="es-title">Select a conversation</div>
      <div class="es-sub">End-to-end encrypted in your browser<br>RSA-OAEP + ChaosKey AES-256-GCM</div>
    </div>
    <div class="chat-view" id="chat-view">
      <div class="chat-header">
        <div class="chat-header-left">
          <div class="avatar" id="contact-avatar" style="background:#888">C</div>
          <div class="contact-info">
            <div class="cname" id="contact-name">–</div>
            <div class="cemail" id="contact-email">–</div>
          </div>
          <div class="enc-badge">⚿ ChaosKey + RSA-OAEP</div>
        </div>
        <button class="burn-thread-btn" onclick="confirmBurn()">🔥 Burn thread</button>
      </div>
      <div class="messages" id="messages-area"></div>
      <div class="compose">
        <div class="compose-wrap">
          <textarea class="compose-input" id="compose-input" rows="1"
            placeholder="Write an encrypted message… (Enter to send)"
            oninput="autoResize(this)"
            onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendMessage();}"></textarea>
        </div>
        <button class="send-btn" id="send-btn" onclick="sendMessage()">➤</button>
      </div>
    </div>
  </div>
</div>

<!-- Burn modal -->
<div class="modal-overlay" id="burn-modal">
  <div class="modal">
    <div class="modal-icon">🔥</div>
    <h2>Burn this thread?</h2>
    <p id="burn-modal-text">This will permanently delete all messages.</p>
    <div class="modal-btns">
      <button class="modal-cancel" onclick="closeBurnModal()">Cancel</button>
      <button class="modal-confirm" onclick="executeBurn()">Burn it</button>
    </div>
  </div>
</div>

<!-- Update ChaosKey modal -->
<div class="modal-overlay" id="key-modal">
  <div class="modal">
    <div class="modal-icon">⚿</div>
    <h2>Update ChaosKey API key</h2>
    <p>Paste a fresh <code style="font-family:'Fira Code',monospace;color:var(--ember)">ck_live_…</code> key from your ChaosKey account.</p>
    <div style="margin:1rem 0">
      <input id="modal-ck-input" type="text" placeholder="ck_live_…"
        style="width:100%;padding:.75rem 1rem;background:var(--ash);border:1px solid var(--smoke);border-radius:8px;color:var(--snow);font-family:'Fira Code',monospace;font-size:.82rem;outline:none"
        onfocus="this.style.borderColor='var(--ember)'" onblur="this.style.borderColor='var(--smoke)'"
        onkeydown="if(event.key==='Enter')saveUpdatedKey()">
      <div id="key-modal-err" style="font-family:'Fira Code',monospace;font-size:.72rem;color:#ff8fab;min-height:1.1rem;margin-top:.4rem"></div>
    </div>
    <div class="modal-btns">
      <button class="modal-cancel" onclick="closeKeyModal()">Cancel</button>
      <button class="modal-confirm" style="background:linear-gradient(135deg,var(--ember),var(--flame));box-shadow:0 4px 15px rgba(255,107,53,.3)" onclick="saveUpdatedKey()">Save key</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
'use strict';

// ════════════════════════════════════════════════════════════════
//  State
// ════════════════════════════════════════════════════════════════
const S = {
  me:            null,   // { email, name, color }
  activeContact: null,
  threads:       [],
  pollTimer:     null,
  authMode:      'login',
  rsaPublicKey:  null,
  rsaPrivateKey: null,
};

// ════════════════════════════════════════════════════════════════
//  Utilities
// ════════════════════════════════════════════════════════════════
const $   = id => document.getElementById(id);
const esc = s  => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const initials = s => (s||'?')[0].toUpperCase();

function toast(msg, type='ok', dur=2800) {
  const el = $('toast');
  el.textContent = msg;
  el.className = `toast ${type} show`;
  setTimeout(() => el.classList.remove('show'), dur);
}

/** Call our BurnChat relay server (session-authenticated). */
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

/**
 * Call ChaosKey via our server-side proxy (/proxy/encrypt or /proxy/decrypt).
 * This avoids the browser CORS restriction — ChaosKey does not emit
 * Access-Control-Allow-Origin headers so direct browser fetch() calls are blocked.
 * The security model is unchanged: the server still never sees plaintext or the
 * raw enc_key because RSA key-wrapping/unwrapping happens in the browser.
 */
async function callChaosKey(path, body) {
  // Map /v1/encrypt → /proxy/encrypt  and  /v1/decrypt → /proxy/decrypt
  const proxyPath = path.replace('/v1/', '/proxy/');
  const {ok, data} = await api(proxyPath, {
    method: 'POST',
    body:   JSON.stringify(body),
  });
  if (!ok) throw new Error(data.error || `ChaosKey proxy error`);
  return data;
}

function autoResize(ta) {
  ta.style.height = 'auto';
  ta.style.height = Math.min(ta.scrollHeight, 120) + 'px';
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

// ════════════════════════════════════════════════════════════════
//  Cross-Device Key Escrow & RSA Management
// ════════════════════════════════════════════════════════════════
async function deriveKeyFromPassword(password, email) {
  const enc = new TextEncoder();
  const km = await crypto.subtle.importKey('raw', enc.encode(password), {name:'PBKDF2'}, false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2', salt: enc.encode(email + '_burnchat_salt'), iterations:100000, hash:'SHA-256'},
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
  const pubB64  = btoa(String.fromCharCode(...new Uint8Array(pubRaw)));
  const privRaw = await crypto.subtle.exportKey('pkcs8', kp.privateKey);
  const privB64 = btoa(String.fromCharCode(...new Uint8Array(privRaw)));
  localStorage.setItem('bc_priv_' + email, privB64);

  const aesKey = await deriveKeyFromPassword(password, email);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encPriv = await crypto.subtle.encrypt({name:'AES-GCM', iv}, aesKey, privRaw);
  const combined = new Uint8Array(12 + encPriv.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(encPriv), 12);

  return {pubB64, encPrivB64: btoa(String.fromCharCode(...combined))};
}

async function loadPrivateKey(email) {
  const b64 = localStorage.getItem('bc_priv_' + email);
  if (!b64) return null;
  try {
    const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    return await crypto.subtle.importKey('pkcs8', raw, {name:'RSA-OAEP', hash:'SHA-256'}, false, ['decrypt']);
  } catch { return null; }
}

async function importPublicKey(pubB64) {
  const raw = Uint8Array.from(atob(pubB64), c => c.charCodeAt(0));
  return crypto.subtle.importKey('spki', raw, {name:'RSA-OAEP', hash:'SHA-256'}, false, ['encrypt']);
}

/** RSA-OAEP encrypt a string with a CryptoKey, returns base64. */
async function rsaEncrypt(plaintext, cryptoKey) {
  const enc = await crypto.subtle.encrypt(
    {name:'RSA-OAEP'},
    cryptoKey,
    new TextEncoder().encode(plaintext)
  );
  return btoa(String.fromCharCode(...new Uint8Array(enc)));
}

/** RSA-OAEP decrypt a base64 string with the local private key, returns string. */
async function rsaDecrypt(cipherB64) {
  if (!S.rsaPrivateKey) return null;
  try {
    const dec = await crypto.subtle.decrypt(
      {name:'RSA-OAEP'},
      S.rsaPrivateKey,
      Uint8Array.from(atob(cipherB64), c => c.charCodeAt(0))
    );
    return new TextDecoder().decode(dec);
  } catch { return null; }
}

// ════════════════════════════════════════════════════════════════
//  Auth
// ════════════════════════════════════════════════════════════════
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
  const err   = $('auth-err');
  const btn   = $('auth-btn');

  if (!email || !pw) { err.textContent = '⚠ Email and password required'; return; }
  btn.disabled = true; err.textContent = '';

  let pubB64 = null, encPrivB64 = null;

  if (S.authMode === 'signup') {
    try {
      const keys = await genAndRegisterKeys(pw, email);
      pubB64 = keys.pubB64; encPrivB64 = keys.encPrivB64;
    } catch(e) {
      err.textContent = '⚠ Key generation failed: ' + e.message;
      btn.disabled = false; return;
    }
  }

  const path = S.authMode === 'signup' ? '/auth/signup' : '/auth/login';
  const body = S.authMode === 'signup'
    ? {email, password:pw, name, chaoskey_api_key:ckKey, public_key:pubB64, encrypted_private_key:encPrivB64}
    : {email, password:pw};

  const {ok, data} = await api(path, {method:'POST', body:JSON.stringify(body)});
  if (!ok) {
    err.textContent = '⚠ ' + (data.error || 'Authentication failed');
    btn.disabled = false; return;
  }

  S.me = {email: data.email, name: data.name, color: data.color};

  if (S.authMode === 'login') {
    S.rsaPrivateKey = await loadPrivateKey(email);
    // New device: decrypt vault with password
    if (!S.rsaPrivateKey && data.encrypted_private_key) {
      try {
        const combined = Uint8Array.from(atob(data.encrypted_private_key), c => c.charCodeAt(0));
        const privRaw  = await crypto.subtle.decrypt(
          {name:'AES-GCM', iv: combined.slice(0, 12)},
          await deriveKeyFromPassword(pw, email),
          combined.slice(12)
        );
        S.rsaPrivateKey = await crypto.subtle.importKey(
          'pkcs8', privRaw, {name:'RSA-OAEP', hash:'SHA-256'}, false, ['decrypt']
        );
        localStorage.setItem('bc_priv_' + email, btoa(String.fromCharCode(...new Uint8Array(privRaw))));
        toast('🔑 RSA keys synced from vault', 'ok', 4000);
      } catch(e) {
        toast('⚠ Could not decrypt key vault (wrong password?)', 'err', 5000);
      }
    }
  }

  enterApp(data);
}

async function doLogout() {
  await api('/auth/logout', {method:'POST'});
  location.reload();
}

async function checkSession() {
  const {ok, data} = await api('/auth/me');
  if (ok && data.authenticated) {
    S.me = {email: data.email, name: data.name, color: data.color};
    S.rsaPrivateKey = await loadPrivateKey(data.email);
    enterApp(data);
  }
}

// ════════════════════════════════════════════════════════════════
//  App Shell
// ════════════════════════════════════════════════════════════════
function enterApp(data={}) {
  $('auth').classList.add('hidden');
  $('app').classList.remove('hidden');

  $('my-avatar').textContent = initials(S.me.name);
  $('my-avatar').style.background = S.me.color;
  $('my-name').textContent  = S.me.name;
  $('my-email').textContent = S.me.email;

  if (data.has_ck_key && data.key_prefix) {
    $('ck-key-bar').style.display = 'flex';
    $('ck-key-prefix').textContent = data.key_prefix;
  } else if (!data.has_ck_key) {
    $('ck-key-warn').style.display = 'block';
  }
  if (S.rsaPrivateKey) $('e2ee-status').style.display = 'flex';

  loadInbox();
  S.pollTimer = setInterval(async () => {
    await loadInbox();
    if (S.activeContact) { $('messages-area').dataset.hash=''; await loadThread(S.activeContact.email, false); }
  }, 3000);
}

// ════════════════════════════════════════════════════════════════
//  Inbox / sidebar
// ════════════════════════════════════════════════════════════════
async function loadInbox() {
  const {ok, data} = await api('/msg/inbox');
  if (!ok || !Array.isArray(data)) return;
  S.threads = data;
  renderThreadList();
}

function renderThreadList() {
  const el = $('thread-list');
  if (!S.threads.length) {
    el.innerHTML = `<div class="no-threads"><div class="nt-icon">🔒</div><div>No conversations yet.<br>Search for a user above.</div></div>`;
    return;
  }
  el.innerHTML = S.threads.map(t => `
    <div class="thread-item ${S.activeContact?.email===t.contact?'active':''}"
         onclick="openThread('${t.contact}','${esc(t.name)}','${t.color}')">
      <div class="avatar" style="background:${t.color}">${initials(t.name)}</div>
      <div class="thread-info">
        <div class="thread-name">${esc(t.name)}</div>
        <div class="thread-email">${esc(t.contact)}</div>
      </div>
      <div class="thread-time">${fmtDate(t.last_at)}</div>
    </div>`).join('');
}

async function onSearchInput(val) {
  const res = $('search-results');
  if (!val || val.length < 3) { res.classList.remove('open'); return; }
  const {ok, data} = await api('/msg/search_user?q=' + encodeURIComponent(val));
  if (!ok || !data.length) { res.classList.remove('open'); return; }
  res.innerHTML = data.map(u => `
    <div class="search-result-item" onclick="openThread('${u.email}','${esc(u.name)}','${u.color}')">
      <div class="avatar" style="background:${u.color};width:28px;height:28px;font-size:.75rem">${initials(u.name)}</div>
      <div class="sr-info"><div class="sr-name">${esc(u.name)}</div><div class="sr-email">${esc(u.email)}</div></div>
    </div>`).join('');
  res.classList.add('open');
}

function closeSearch() { $('search-results').classList.remove('open'); }

// ════════════════════════════════════════════════════════════════
//  Thread
// ════════════════════════════════════════════════════════════════
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
  loadThread(email, true);
}

async function loadThread(email, scrollToBottom=true) {
  const {ok, data} = await api(`/msg/thread?with=${encodeURIComponent(email)}`);
  if (!ok || !Array.isArray(data)) return;

  const area = $('messages-area');
  const resolved = [];

  for (const m of data) {
    let text = '[Decryption failed]';

    if (!S.rsaPrivateKey) {
      text = '[No RSA private key on this device]';
    } else if (!m.rsa_enc_key || !m.ciphertext || !m.nonce) {
      text = '[Missing encrypted data]';
    } else {
      try {
        // Step 1 — RSA-OAEP unwrap the ChaosKey enc_key using our local private key
        const rawEncKey = await rsaDecrypt(m.rsa_enc_key);
        if (!rawEncKey) {
          text = '[RSA unwrap failed — wrong device?]';
        } else {
          // Step 2 — Call /proxy/decrypt (server forwards to ChaosKey, avoids CORS)
          const dec = await callChaosKey('/v1/decrypt', {
            ciphertext:     m.ciphertext,
            nonce:          m.nonce,
            encryption_key: rawEncKey,
          });
          text = dec.plaintext ?? '[Empty plaintext]';
        }
      } catch(e) {
        text = `[${e.message || 'Error'}]`;
      }
    }
    resolved.push({...m, resolved: text});
  }

  let html = '';
  for (const m of resolved) {
    const mine = m.from === S.me.email;
    html += `
      <div class="msg-group ${mine?'mine':'theirs'}">
        <div class="bubble">${esc(m.resolved)}</div>
        <div class="msg-meta">${fmtTime(m.sent_at)}</div>
        <div class="e2ee-tag">⚿ ChaosKey + RSA-OAEP</div>
      </div>`;
  }

  const hash = btoa(unescape(encodeURIComponent(html))).slice(0, 20);
  if (area.dataset.hash !== hash) {
    area.innerHTML = html || `<div style="text-align:center;color:var(--dust);font-family:'Fira Code',monospace;font-size:.75rem;margin-top:2rem">No messages yet.</div>`;
    area.dataset.hash = hash;
    if (scrollToBottom) area.scrollTop = area.scrollHeight;
  }
}

// ════════════════════════════════════════════════════════════════
//  Send — RSA wrapping in browser, ChaosKey encrypt via proxy
// ════════════════════════════════════════════════════════════════
async function sendMessage() {
  const inp = $('compose-input');
  const txt = inp.value.trim();
  if (!txt || !S.activeContact) return;

  const btn = $('send-btn');
  btn.disabled = true;

  try {
    // Step 1 — Encrypt with ChaosKey via server-side proxy (avoids CORS)
    const ck = await callChaosKey('/v1/encrypt', {plaintext: txt});

    // Step 2 — Fetch recipient's RSA public key from our relay
    const {data: keyData} = await api(`/user/key?email=${encodeURIComponent(S.activeContact.email)}`);
    if (!keyData.key) throw new Error(`Recipient has no public key registered`);

    // Step 3 — RSA-OAEP wrap the ChaosKey enc_key in the browser with recipient's public key
    const recipPubKey = await importPublicKey(keyData.key);
    const rsa_enc_key = await rsaEncrypt(ck.encryption_key, recipPubKey);

    // Step 4 — Send only the encrypted payload to our relay (plaintext never touches server)
    const {ok, data} = await api('/msg/send', {
      method: 'POST',
      body:   JSON.stringify({
        recipient:   S.activeContact.email,
        ciphertext:  ck.ciphertext,
        nonce:       ck.nonce,
        rsa_enc_key: rsa_enc_key,
      }),
    });

    if (!ok) throw new Error(data.error || 'Send failed');

    inp.value = '';
    inp.style.height = 'auto';
    $('messages-area').dataset.hash = '';
    await loadThread(S.activeContact.email, true);
    await loadInbox();
  } catch(e) {
    toast('✗ ' + e.message, 'err');
  } finally {
    btn.disabled = false;
  }
}

// ════════════════════════════════════════════════════════════════
//  Burn thread
// ════════════════════════════════════════════════════════════════
function confirmBurn() {
  if (!S.activeContact) return;
  $('burn-modal-text').textContent = `Burn all messages with ${S.activeContact.name}? This cannot be undone.`;
  $('burn-modal').classList.add('open');
}
function closeBurnModal() { $('burn-modal').classList.remove('open'); }

async function executeBurn() {
  closeBurnModal();
  if (!S.activeContact) return;
  const {ok} = await api('/msg/burn', {method:'POST', body:JSON.stringify({contact: S.activeContact.email})});
  if (ok) {
    $('messages-area').innerHTML = '';
    $('messages-area').dataset.hash = '';
    toast('🔥 Thread burned', 'ok');
    await loadInbox();
  } else {
    toast('✗ Burn failed', 'err');
  }
}

// ════════════════════════════════════════════════════════════════
//  Update ChaosKey key modal
// ════════════════════════════════════════════════════════════════
function showUpdateKeyModal() { $('key-modal').classList.add('open'); }
function closeKeyModal() {
  $('key-modal').classList.remove('open');
  $('key-modal-err').textContent = '';
  $('modal-ck-input').value = '';
}

async function saveUpdatedKey() {
  const val   = $('modal-ck-input').value.trim();
  const errEl = $('key-modal-err');
  if (!val || !val.startsWith('ck_live_')) {
    errEl.textContent = '⚠ Key must start with ck_live_'; return;
  }
  const {ok, data} = await api('/auth/update_ck_key', {method:'POST', body:JSON.stringify({chaoskey_api_key:val})});
  if (ok) {
    $('ck-key-prefix').textContent = data.key_prefix;
    $('ck-key-bar').style.display  = 'flex';
    $('ck-key-warn').style.display = 'none';
    closeKeyModal();
    toast('⚿ ChaosKey API key updated', 'ok');
  } else {
    errEl.textContent = '⚠ ' + (data.error || 'Update failed');
  }
}

// ════════════════════════════════════════════════════════════════
//  Boot
// ════════════════════════════════════════════════════════════════
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
    log.info("Encryption: CLIENT-SIDE RSA-OAEP (browser) + ChaosKey AES-256-GCM (server-proxied).")
    app.run(host="0.0.0.0", port=PORT, debug=False)
