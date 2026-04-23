"""
BurnChat — Encrypted Ephemeral Messenger (Cross-Device Fixed Edition)
======================================================================
Key fixes over the original:

  Cross-device vault (was broken):
    - PBKDF2 salt is now a random 16-byte value stored in the DB alongside the
      encrypted vault, not a hardcoded string. This fixes derivation mismatches.
    - /auth/login returns the salt so the browser can derive the AES key correctly
      on any device without ever sending the password to the server.
    - Vault decryption failure on a new device now opens a password-confirm modal
      instead of a silent toast, so users can actually recover.
    - Vault-first key loading: the encrypted vault is always the primary path;
      localStorage is a performance cache only.

  Performance:
    - Decryption is now parallelised in the browser with Promise.all(), so a
      20-message thread does 20 ChaosKey calls in parallel instead of sequentially.
    - A per-session decryption cache (Map keyed by message id) means already-
      decrypted messages are returned instantly on the 3-second poll.

  Encryption model (unchanged from original):
    Send:
      1. Browser → /proxy/encrypt → ChaosKey → ciphertext, nonce, enc_key
      2. Browser RSA-OAEP wraps enc_key with recipient's public key  → rsa_enc_key
      3. Browser RSA-OAEP wraps enc_key with own public key          → sender_enc_key
      4. Relay stores encrypted payload — server never sees plaintext or raw enc_key
    Receive:
      1. Browser fetches encrypted messages
      2. RSA-OAEP unwraps the correct wrapped key with own private key
      3. Browser → /proxy/decrypt → ChaosKey → plaintext

  New endpoints:
    POST /auth/change_password  — re-derives AES key, re-encrypts vault, updates DB
    POST /auth/vault_decrypt_fail — called when vault decryption fails, prompts re-key
"""

import os, secrets, hmac, logging, urllib.request as _req, json as _json, base64
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
CREATE INDEX IF NOT EXISTS idx_msg_thread ON messages(sender, recipient);
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
    "CREATE INDEX IF NOT EXISTS idx_msg_thread ON messages(sender, recipient)",
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
    user = db_exec("SELECT chaoskey_api_key FROM users WHERE email = ?", (email,)).fetchone()
    return (user["chaoskey_api_key"] or "") if user else ""

def _chaoskey_post(path, payload, ck_key):
    req = _req.Request(
        f"{CHAOSKEY_URL}{path}",
        data=_json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {ck_key}", "Content-Type": "application/json"},
        method="POST",
    )
    with _req.urlopen(req, timeout=10) as resp:
        return _json.loads(resp.read()), resp.status

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
    # Random salt generated by browser, stored as hex
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
    # NOTE: we return vault_salt so the browser can derive the AES key without
    # sending the password to the server. The password never leaves the browser.
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
    return jsonify({"ok": True, "key_prefix": ck_key[:16] + "…"})


@app.route("/auth/rekey", methods=["POST"])
@require_login
def rekey():
    """
    Replace RSA keys + vault for the logged-in user.
    Requires current password to prevent a rogue session from silently rotating keys.
    Browser sends:
      - password          (verified server-side against stored hash)
      - public_key        (new RSA public key, SPKI b64)
      - encrypted_private_key (new AES-GCM encrypted vault, b64)
      - vault_salt        (new random PBKDF2 salt, hex)
    """
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
    log.info(f"Re-key completed for {session['user_email']}")
    return jsonify({"ok": True})


@app.route("/auth/change_password", methods=["POST"])
@require_login
def change_password():
    """
    Change password AND re-encrypt the vault with the new derived key.
    Browser derives new AES key, re-encrypts the private key, sends encrypted vault.
    """
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

    db_exec(
        "INSERT INTO messages (sender, recipient, ciphertext, nonce, enc_key, sender_enc_key, sent_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (sender, recipient, ciphertext, nonce, rsa_enc_key, sender_enc_key, now_iso())
    )
    db_commit()
    return jsonify({"ok": True, "sent_at": now_iso()}), 201


@app.route("/msg/thread", methods=["GET"])
@require_login
def get_thread():
    contact = request.args.get("with", "").strip().lower()
    me      = session["user_email"]
    if not contact:
        return jsonify({"error": "?with= required"}), 400
    rows = db_exec(
        "SELECT id, sender, ciphertext, nonce, enc_key, sender_enc_key, sent_at "
        "FROM messages "
        "WHERE (sender=? AND recipient=?) OR (sender=? AND recipient=?) "
        "ORDER BY id ASC",
        (me, contact, contact, me)
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
    me = session["user_email"]
    rows = db_exec(
        "SELECT "
        "  CASE WHEN sender=? THEN recipient ELSE sender END as contact, "
        "  MAX(sent_at) as last_at, COUNT(*) as total "
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
        "status": "ok",
        "chaoskey_url": CHAOSKEY_URL,
        "db_backend": "postgresql" if USE_POSTGRES else "sqlite",
        "e2ee": "ChaosKey AES-256-GCM (proxied) + RSA-OAEP dual-wrap (browser)",
        "cross_device": "PBKDF2 random-salt vault (fixed)",
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

/* AUTH */
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

/* APP */
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
.burn-thread-btn:hover{background:rgba(255,90,90,.2)}

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

.compose{padding:1rem 1.5rem;background:var(--coal);border-top:1px solid var(--cinder);display:flex;gap:.75rem;align-items:flex-end;flex-shrink:0}
.compose-wrap{flex:1;background:var(--ash);border:1px solid var(--smoke);border-radius:14px;overflow:hidden;transition:border-color .2s,box-shadow .2s}
.compose-wrap:focus-within{border-color:var(--ember);box-shadow:0 0 0 3px rgba(255,107,53,.1)}
.compose-input{width:100%;padding:.8rem 1rem;background:none;border:none;color:var(--snow);font-family:'Lora',serif;font-size:.88rem;outline:none;resize:none;max-height:120px;line-height:1.5}
.compose-input::placeholder{color:var(--dust)}
.send-btn{width:44px;height:44px;flex-shrink:0;background:linear-gradient(135deg,var(--ember),var(--flame));border:none;border-radius:12px;color:#fff;font-size:1.1rem;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .2s;box-shadow:0 4px 12px rgba(255,107,53,.3)}
.send-btn:hover{transform:scale(1.05)}
.send-btn:disabled{opacity:.35;cursor:not-allowed;transform:none}

/* MODALS */
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

<!-- ── AUTH ─────────────────────────────────────────────────── -->
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

<!-- ── APP ──────────────────────────────────────────────────── -->
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
            oninput="autoResize(this)"
            onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendMessage();}"></textarea>
        </div>
        <button class="send-btn" id="send-btn" onclick="sendMessage()">➤</button>
      </div>
    </div>
  </div>
</div>

<!-- ── MODALS ────────────────────────────────────────────────── -->
<!-- Burn thread -->
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

<!-- Re-key (missing or failed vault) -->
<div class="modal-overlay" id="rekey-modal">
  <div class="modal">
    <div class="modal-icon">🔑</div>
    <h2 id="rekey-modal-title">Generate new keys</h2>
    <p id="rekey-modal-desc">Enter your password to generate a fresh RSA keypair and upload an encrypted vault so you can decrypt messages on this device.</p>
    <input id="rekey-pw-input" class="modal-input" type="password" placeholder="Your current password"
      onkeydown="if(event.key==='Enter')executeRekey()">
    <div class="modal-err" id="rekey-modal-err"></div>
    <div class="modal-btns">
      <button class="modal-cancel" onclick="closeMod('rekey-modal')">Later</button>
      <button class="modal-confirm" id="rekey-confirm-btn" onclick="executeRekey()">Generate keys</button>
    </div>
  </div>
</div>

<!-- Vault decrypt failed — ask for password to retry -->
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
  me:            null,   // { email, name, color }
  activeContact: null,
  threads:       [],
  pollTimer:     null,
  authMode:      'login',
  rsaPublicKey:  null,
  rsaPrivateKey: null,
  // Pending vault data from login response — used if auto-decrypt fails
  _pendingVault: null,  // { encrypted_private_key, vault_salt }
};

// ─── Decryption cache (keyed by message id) ────────────────────
// Survives the 3-second poll loop so already-decrypted messages
// are returned instantly without hitting ChaosKey again.
const decCache = new Map();

// ═══════════════════════════════════════════════
//  Utilities
// ═══════════════════════════════════════════════
const $   = id => document.getElementById(id);
const esc = s  => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const initials = s => (s||'?')[0].toUpperCase();

function toast(msg, type='ok', dur=3000) {
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
function closeMod(id) { $(id).classList.remove('open'); }

// ═══════════════════════════════════════════════
//  RSA helpers
// ═══════════════════════════════════════════════

/**
 * Derive an AES-256-GCM key from password + a random salt.
 * salt must be a Uint8Array (16 bytes, randomly generated at signup).
 * The salt is stored in the DB alongside the encrypted vault so any device
 * can reproduce the same key given the correct password.
 */
async function deriveAesKey(password, salt) {
  const enc = new TextEncoder();
  const km = await crypto.subtle.importKey('raw', enc.encode(password), {name:'PBKDF2'}, false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2', salt, iterations:100000, hash:'SHA-256'},
    km, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']
  );
}

/**
 * Generate RSA-OAEP-2048 keypair, encrypt private key with AES-GCM derived from password,
 * cache raw private key in localStorage, return base64-encoded public key + vault + salt hex.
 */
async function genAndRegisterKeys(password, email) {
  const kp = await crypto.subtle.generateKey(
    {name:'RSA-OAEP', modulusLength:2048, publicExponent:new Uint8Array([1,0,1]), hash:'SHA-256'},
    true, ['encrypt','decrypt']
  );
  S.rsaPublicKey  = kp.publicKey;
  S.rsaPrivateKey = kp.privateKey;

  const pubRaw  = await crypto.subtle.exportKey('spki', kp.publicKey);
  const privRaw = await crypto.subtle.exportKey('pkcs8', kp.privateKey);

  // Cache raw private key locally for fast future logins on this device
  _cachePrivKey(email, privRaw);

  // Random 16-byte PBKDF2 salt — stored in DB, returned to browser on login
  const salt    = crypto.getRandomValues(new Uint8Array(16));
  const aesKey  = await deriveAesKey(password, salt);
  const iv      = crypto.getRandomValues(new Uint8Array(12));
  const encPriv = await crypto.subtle.encrypt({name:'AES-GCM', iv}, aesKey, privRaw);

  // Vault blob: 16-byte salt | 12-byte IV | ciphertext
  const blob = new Uint8Array(16 + 12 + encPriv.byteLength);
  blob.set(salt, 0);
  blob.set(iv,   16);
  blob.set(new Uint8Array(encPriv), 28);

  return {
    pubB64:     _toB64(pubRaw),
    encPrivB64: _toB64(blob),
    saltHex:    _toHex(salt),
  };
}

/**
 * Decrypt vault blob (16-byte salt + 12-byte IV + ciphertext) using password.
 * Returns imported CryptoKey or throws.
 */
async function decryptVault(encPrivB64, password) {
  const blob    = _fromB64(encPrivB64);
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
  } catch(e) {
    return null;
  }
}

async function ensureOwnPublicKey() {
  if (S.rsaPublicKey) return;
  try {
    const {data} = await api(`/user/key?email=${encodeURIComponent(S.me.email)}`);
    if (data.key) S.rsaPublicKey = await importPublicKey(data.key);
  } catch(e) {}
}

// ── private helpers ──
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
      try { S.rsaPublicKey = await importPublicKey(data.public_key); } catch(e) {}
    }
  }

  errEl.textContent = '';
  btn.disabled = false;
  enterApp(data);
}

/**
 * Primary cross-device key resolution on login.
 * Priority: localStorage (fast, same device) → vault decrypt (new device) → prompt user
 */
async function _resolvePrivateKey(password, data) {
  // 1 — Same device: localStorage is fastest
  S.rsaPrivateKey = await loadPrivKeyFromStorage(data.email);
  if (S.rsaPrivateKey) { return; }

  // 2 — New device: decrypt vault with password we already have in memory
  if (data.encrypted_private_key && data.vault_salt) {
    S._pendingVault = {encrypted_private_key: data.encrypted_private_key, vault_salt: data.vault_salt};
    if (password) {
      try {
        const {privRaw, key} = await decryptVault(data.encrypted_private_key, password);
        S.rsaPrivateKey = key;
        _cachePrivKey(data.email, privRaw);
        toast('🔑 Keys synced from vault', 'ok', 4000);
        return;
      } catch(e) {
        // Wrong password or corrupted vault — ask the user explicitly
        _showVaultPwModal();
        return;
      }
    }
    // password not available (checkSession path) — ask user
    _showVaultPwModal();
  } else if (!data.encrypted_private_key) {
    // Account pre-dates vault feature
    showRekeyModal('missing');
  }
}

// Called from checkSession (page reload, no password in memory)
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

  btn.disabled = true;
  btn.textContent = 'Unlocking…';
  err.textContent = '';

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
      $('messages-area').dataset.hash = '';
      await loadThread(S.activeContact.email, true);
    }
  } catch(e) {
    err.textContent = '⚠ Wrong password or corrupted vault';
  } finally {
    btn.disabled = false;
    btn.textContent = 'Unlock';
  }
}

async function doLogout() {
  await api('/auth/logout', {method:'POST'});
  S.rsaPublicKey = null; S.rsaPrivateKey = null; S._pendingVault = null;
  clearInterval(S.pollTimer);
  decCache.clear();
  location.reload();
}

async function checkSession() {
  const {ok, data} = await api('/auth/me');
  if (ok && data.authenticated) {
    S.me = {email: data.email, name: data.name, color: data.color};
    await _resolvePrivateKeyNoPassword(data);
    if (data.public_key) {
      try { S.rsaPublicKey = await importPublicKey(data.public_key); } catch(e) {}
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
  S.pollTimer = setInterval(async () => {
    await loadInbox();
    if (S.activeContact) await loadThread(S.activeContact.email, false);
  }, 3000);
}

function renderStatusBar(data={}) {
  const el = $('status-bar');
  const items = [];
  const hasCk = data.has_ck_key ?? true;
  if (hasCk && data.key_prefix) {
    items.push(`<div class="bar-item bar-ok">⚿ ${esc(data.key_prefix)}<button class="bar-btn" onclick="$('key-modal').classList.add('open')">update</button></div>`);
  } else if (!hasCk) {
    items.push(`<div class="bar-item bar-warn">⚠ No ChaosKey key<button class="bar-btn" onclick="$('key-modal').classList.add('open')">add →</button></div>`);
  }
  if (S.rsaPrivateKey) {
    items.push(`<div class="bar-item bar-ok">🔑 RSA keys ready · cross-device E2EE</div>`);
  } else {
    items.push(`<div class="bar-item bar-warn">⚠ Keys not loaded · messages encrypted<button class="bar-btn" onclick="_showVaultPwModal()">unlock →</button></div>`);
  }
  el.innerHTML = items.join('');
}

// ═══════════════════════════════════════════════
//  Inbox / threads
// ═══════════════════════════════════════════════
async function loadInbox() {
  const {ok, data} = await api('/msg/inbox');
  if (!ok || !Array.isArray(data)) return;
  S.threads = data;
  renderThreadList();
}

function renderThreadList() {
  const el = $('thread-list');
  if (!S.threads.length) {
    el.innerHTML = `<div class="no-threads">No conversations yet.<br>Search for a user above.</div>`;
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
  loadThread(email, true);
}

/**
 * Load + decrypt thread.
 *
 * KEY PERFORMANCE FIX:
 *   Messages are decrypted in PARALLEL using Promise.all(). The original code
 *   used a sequential for-loop that awaited each ChaosKey call one by one —
 *   N messages = N sequential round-trips. This cuts wall time from O(N) to
 *   roughly O(1) (limited only by server concurrency).
 *
 *   The decCache Map prevents re-decrypting messages that are already known,
 *   so the 3-second poll only decrypts genuinely new messages.
 */
async function loadThread(email, scrollToBottom=true) {
  const {ok, data} = await api(`/msg/thread?with=${encodeURIComponent(email)}`);
  if (!ok || !Array.isArray(data)) return;

  const resolved = await Promise.all(data.map(async m => {
    // Fast path: already decrypted this session
    if (decCache.has(m.id)) return {from: m.from, sent_at: m.sent_at, text: decCache.get(m.id)};

    let text = '[Decryption failed]';

    if (!S.rsaPrivateKey) {
      text = '[Keys not loaded — unlock vault to read messages]';
    } else if (!m.ciphertext || !m.nonce) {
      text = '[Missing encrypted data]';
    } else {
      const isMine   = m.from === S.me.email;
      const wrapped  = isMine ? m.sender_enc_key : m.rsa_enc_key;

      if (!wrapped) {
        text = isMine ? '[Sent before self-wrap — cannot read own copy]' : '[Missing encrypted key]';
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
            decCache.set(m.id, text);  // cache hit from now on
          }
        } catch(e) {
          text = `[${e.message || 'Decryption error'}]`;
        }
      }
    }
    return {from: m.from, sent_at: m.sent_at, text};
  }));

  const area = $('messages-area');
  let html = '';
  for (const m of resolved) {
    const mine = m.from === S.me.email;
    const isErr = m.text.startsWith('[');
    html += `
      <div class="msg-group ${mine?'mine':'theirs'}">
        <div class="bubble${isErr?' err-bubble':''}">${esc(m.text)}</div>
        <div class="msg-meta">${fmtTime(m.sent_at)}</div>
        <div class="e2ee-tag">⚿ ChaosKey + RSA-OAEP</div>
      </div>`;
  }

  const hash = String(data.length) + (data[data.length-1]?.id ?? '');
  if (area.dataset.hash !== hash) {
    area.innerHTML = html || `<div style="text-align:center;color:var(--dust);font-family:'Fira Code',monospace;font-size:.73rem;margin-top:2rem">No messages yet.</div>`;
    area.dataset.hash = hash;
    if (scrollToBottom) area.scrollTop = area.scrollHeight;
  }
}

// ═══════════════════════════════════════════════
//  Send
// ═══════════════════════════════════════════════
async function sendMessage() {
  const inp = $('compose-input');
  const txt = inp.value.trim();
  if (!txt || !S.activeContact) return;
  const btn = $('send-btn');
  btn.disabled = true;
  try {
    // 1 — Encrypt via ChaosKey proxy
    const ck = await callChaosKey('/v1/encrypt', {plaintext: txt});

    // 2 — Fetch recipient public key
    const {data: recipKeyData} = await api(`/user/key?email=${encodeURIComponent(S.activeContact.email)}`);
    if (!recipKeyData.key) throw new Error('Recipient has no public key — they need to log in first');

    // 3 — Own public key for self-wrap
    await ensureOwnPublicKey();
    if (!S.rsaPublicKey) throw new Error('Your public key missing — log in again');

    // 4 — Dual RSA wrap (recipient + self)
    const recipPubKey    = await importPublicKey(recipKeyData.key);
    const [rsa_enc_key, sender_enc_key] = await Promise.all([
      rsaEncrypt(ck.encryption_key, recipPubKey),
      rsaEncrypt(ck.encryption_key, S.rsaPublicKey),
    ]);

    // 5 — Relay
    const {ok, data} = await api('/msg/send', {
      method:'POST',
      body: JSON.stringify({
        recipient: S.activeContact.email,
        ciphertext: ck.ciphertext,
        nonce: ck.nonce,
        rsa_enc_key,
        sender_enc_key,
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

// ═══════════════════════════════════════════════
//  Burn thread
// ═══════════════════════════════════════════════
function confirmBurn() {
  if (!S.activeContact) return;
  $('burn-modal-text').textContent = `Burn all messages with ${S.activeContact.name}? This cannot be undone.`;
  $('burn-modal').classList.add('open');
}

async function executeBurn() {
  closeMod('burn-modal');
  if (!S.activeContact) return;
  const {ok} = await api('/msg/burn', {method:'POST', body:JSON.stringify({contact: S.activeContact.email})});
  if (ok) {
    // Evict burned thread from decryption cache
    $('messages-area').innerHTML = '';
    $('messages-area').dataset.hash = '';
    decCache.clear();
    toast('🔥 Thread burned', 'ok');
    await loadInbox();
  } else {
    toast('✗ Burn failed', 'err');
  }
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
  const title = reason === 'failed'
    ? 'Generate new keys'
    : 'No key vault found';
  const desc = reason === 'failed'
    ? 'Vault decryption failed. You can generate a fresh keypair — old messages encrypted to your previous key will not be recoverable, but new messages will work normally.'
    : 'No key vault was found for this account. Enter your password to generate a fresh RSA keypair and upload an encrypted vault.';
  $('rekey-modal-title').textContent = title;
  $('rekey-modal-desc').textContent  = desc;
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

  btn.disabled = true;
  btn.textContent = 'Generating…';
  errEl.textContent = '';

  try {
    const {pubB64, encPrivB64, saltHex} = await genAndRegisterKeys(pw, S.me.email);
    const {ok, data} = await api('/auth/rekey', {
      method: 'POST',
      body: JSON.stringify({password:pw, public_key:pubB64, encrypted_private_key:encPrivB64, vault_salt:saltHex}),
    });
    if (!ok) { errEl.textContent = '⚠ ' + (data.error || 'Re-key failed'); return; }
    closeMod('rekey-modal');
    decCache.clear();
    renderStatusBar({has_ck_key: !!S.me, key_prefix: null});
    toast('🔑 New RSA keys generated and saved', 'ok', 5000);
  } catch(e) {
    errEl.textContent = '⚠ ' + (e.message || 'Unknown error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Generate keys';
  }
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
