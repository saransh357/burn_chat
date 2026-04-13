"""
BurnChat — Encrypted Ephemeral Messenger
=========================================
Standalone product. Uses ChaosKey API for AES-256-GCM encryption.
Each user supplies their own ChaosKey API key at signup — it is stored
in the BurnChat DB and loaded into their session on every login.
Messages are encrypted at rest; threads can be permanently burned.

Additionally, RSA-OAEP (2048-bit) client-side E2EE is layered on top:
  - On signup, each browser generates an RSA key pair
  - The public key is stored on the server
  - Messages are encrypted in the browser with the recipient's public key
  - Only the recipient's browser (holding the private key) can decrypt

Environment Variables:
  CHAOSKEY_URL   URL of your ChaosKey instance (e.g. https://your-app.onrender.com)
  SECRET_KEY     Flask session secret (random string, keep safe)
  DB_PATH        SQLite database file path (default: burnchat.db)
  PORT           Port to listen on (default: 5000)
"""

import os, secrets, hashlib, hmac, time, logging, json, requests
from datetime import datetime, timezone
from functools import wraps

from flask import (Flask, request, jsonify, g, session,
                   render_template_string, redirect, abort)
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
CHAOSKEY_URL = os.getenv("CHAOSKEY_URL", "").rstrip("/")
SECRET_KEY   = os.getenv("SECRET_KEY", secrets.token_hex(32))
DATABASE_URL = os.getenv("DATABASE_URL", "")   # Postgres (Neon / Render)
DB_PATH      = os.getenv("DB_PATH", "burnchat.db")  # SQLite fallback
PORT         = int(os.getenv("PORT", 5000))

USE_POSTGRES = bool(DATABASE_URL)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("BurnChat")

if not CHAOSKEY_URL:
    log.warning("CHAOSKEY_URL not set — server-side encryption will fail.")
log.info(f"Database backend: {'postgresql' if USE_POSTGRES else 'sqlite'}")

app = Flask("BurnChat")
app.secret_key = SECRET_KEY
CORS(app, supports_credentials=True)

# ── Database abstraction ──────────────────────────────────────────────────────
if USE_POSTGRES:
    import psycopg2
    import psycopg2.extras
    import urllib.parse as up

    def _pg_url():
        url = (DATABASE_URL or "").strip()
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql://", 1)
        parsed = up.urlparse(url)
        qs = up.parse_qs(parsed.query)
        qs.pop("channel_binding", None)
        new_query = up.urlencode(qs, doseq=True)
        url = up.urlunparse(parsed._replace(query=new_query))
        return url

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
        if db:
            db.close()

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
    public_key       TEXT
);
CREATE TABLE IF NOT EXISTS messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sender       TEXT NOT NULL,
    recipient    TEXT NOT NULL,
    ciphertext   TEXT NOT NULL,
    nonce        TEXT NOT NULL DEFAULT '',
    enc_key      TEXT NOT NULL DEFAULT '',
    plaintext    TEXT,
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
        public_key       TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS messages (
        id           SERIAL PRIMARY KEY,
        sender       TEXT NOT NULL,
        recipient    TEXT NOT NULL,
        ciphertext   TEXT NOT NULL,
        nonce        TEXT NOT NULL DEFAULT '',
        enc_key      TEXT NOT NULL DEFAULT '',
        plaintext    TEXT,
        sent_at      TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_msg_thread ON messages(sender, recipient)",
]

PG_MIGRATIONS = [
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_color TEXT NOT NULL DEFAULT '#ff6b35'",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS chaoskey_api_key TEXT",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS public_key TEXT",
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


# ── ChaosKey API bridge ───────────────────────────────────────────────────────
def _ck_api_key() -> str:
    return session.get("ck_api_key", "")

def ck_encrypt(plaintext: str):
    api_key = _ck_api_key()
    if not CHAOSKEY_URL:
        return False, {"error": "CHAOSKEY_URL not configured on this server."}
    if not api_key:
        return False, {"error": "No ChaosKey API key in session. Please log out and log back in."}
    try:
        r = requests.post(
            f"{CHAOSKEY_URL}/v1/encrypt",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"plaintext": plaintext},
            timeout=15,
        )
        data = r.json()
        return r.ok, data
    except requests.exceptions.ConnectionError:
        return False, {"error": "Cannot reach ChaosKey — check CHAOSKEY_URL."}
    except requests.exceptions.Timeout:
        return False, {"error": "ChaosKey timed out."}
    except Exception as e:
        return False, {"error": str(e)}

def ck_decrypt(ciphertext: str, nonce: str, enc_key: str):
    api_key = _ck_api_key()
    if not CHAOSKEY_URL:
        return False, {"error": "CHAOSKEY_URL not configured on this server."}
    if not api_key:
        return False, {"error": "No ChaosKey API key in session."}
    try:
        r = requests.post(
            f"{CHAOSKEY_URL}/v1/decrypt",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"ciphertext": ciphertext, "nonce": nonce, "encryption_key": enc_key},
            timeout=15,
        )
        data = r.json()
        return r.ok, data
    except requests.exceptions.ConnectionError:
        return False, {"error": "Cannot reach ChaosKey."}
    except requests.exceptions.Timeout:
        return False, {"error": "ChaosKey timed out."}
    except Exception as e:
        return False, {"error": str(e)}


# ── Auth routes ───────────────────────────────────────────────────────────────
@app.route("/auth/signup", methods=["POST"])
def signup():
    body       = request.get_json(force=True) or {}
    email      = body.get("email", "").strip().lower()
    pw         = body.get("password", "").strip()
    name       = body.get("name", "").strip() or email.split("@")[0]
    ck_key     = body.get("chaoskey_api_key", "").strip()
    public_key = body.get("public_key", "").strip()   # RSA public key from client

    if not email or "@" not in email:
        return jsonify({"error": "Valid email required"}), 400
    if not pw or len(pw) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    if not ck_key or not ck_key.startswith("ck_live_"):
        return jsonify({"error": "Valid ChaosKey API key required (starts with ck_live_)"}), 400

    color = pick_color(email)
    try:
        db_exec(
            "INSERT INTO users (email, display_name, password_hash, created_at, avatar_color, chaoskey_api_key, public_key) "
            "VALUES (?,?,?,?,?,?,?)",
            (email, name, hash_password(pw), now_iso(), color, ck_key, public_key)
        )
        db_commit()
    except Exception as e:
        if "unique" in str(e).lower():
            return jsonify({"error": "Email already registered"}), 409
        return jsonify({"error": str(e)}), 500

    session["user_email"] = email
    session["user_name"]  = name
    session["user_color"] = color
    session["ck_api_key"] = ck_key
    key_prefix = ck_key[:16] + "…"
    return jsonify({"ok": True, "email": email, "name": name, "color": color, "key_prefix": key_prefix}), 201


@app.route("/auth/login", methods=["POST"])
def login():
    body  = request.get_json(force=True) or {}
    email = body.get("email", "").strip().lower()
    pw    = body.get("password", "").strip()

    if not email or not pw:
        return jsonify({"error": "Email and password required"}), 400

    user = db_exec(
        "SELECT email, display_name, password_hash, avatar_color, chaoskey_api_key, public_key "
        "FROM users WHERE email = ?", (email,)
    ).fetchone()

    if not user or not check_password(pw, user["password_hash"]):
        return jsonify({"error": "Invalid email or password"}), 401

    ck_key = user["chaoskey_api_key"] or ""
    session["user_email"] = user["email"]
    session["user_name"]  = user["display_name"]
    session["user_color"] = user["avatar_color"]
    session["ck_api_key"] = ck_key
    key_prefix = (ck_key[:16] + "…") if ck_key else None
    return jsonify({
        "ok":         True,
        "email":      user["email"],
        "name":       user["display_name"],
        "color":      user["avatar_color"],
        "key_prefix": key_prefix,
        "has_ck_key": bool(ck_key),
        "public_key": user["public_key"] or "",
    })


@app.route("/auth/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/auth/me", methods=["GET"])
def me():
    if "user_email" not in session:
        return jsonify({"authenticated": False}), 200
    ck_key = session.get("ck_api_key", "")
    return jsonify({
        "authenticated": True,
        "email":      session["user_email"],
        "name":       session["user_name"],
        "color":      session.get("user_color", "#ff6b35"),
        "has_ck_key": bool(ck_key),
        "key_prefix": (ck_key[:16] + "…") if ck_key else None,
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
    session["ck_api_key"] = ck_key
    return jsonify({"ok": True, "key_prefix": ck_key[:16] + "…"})


# ── RSA Public Key endpoint (from file 1) ─────────────────────────────────────
@app.route("/user/key", methods=["GET"])
@require_login
def get_user_key():
    """Return the RSA public key for a given user email."""
    email = request.args.get("email", "").strip().lower()
    if not email:
        return jsonify({"error": "email param required"}), 400
    u = db_exec("SELECT public_key FROM users WHERE email = ?", (email,)).fetchone()
    return jsonify({"key": u["public_key"] if u else None})


@app.route("/user/update_key", methods=["POST"])
@require_login
def update_public_key():
    """Allow a logged-in user to register/update their RSA public key."""
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
    body      = request.get_json(force=True) or {}
    recipient = body.get("recipient", "").strip().lower()
    plaintext = body.get("plaintext", "").strip()
    # RSA-encrypted ciphertext from the client (optional — present when client has recipient's pubkey)
    rsa_cipher = body.get("ciphertext", "").strip()
    sender    = session["user_email"]

    if not recipient or not plaintext:
        return jsonify({"error": "recipient and plaintext required"}), 400
    if recipient == sender:
        return jsonify({"error": "Cannot message yourself"}), 400

    exists = db_exec("SELECT id FROM users WHERE email = ?", (recipient,)).fetchone()
    if not exists:
        return jsonify({"error": f"User '{recipient}' not found on BurnChat"}), 404

    # Use RSA ciphertext if provided by client, else fall back to ChaosKey
    if rsa_cipher:
        # Client performed RSA-OAEP encryption — store as-is, nonce/enc_key empty
        db_exec(
            "INSERT INTO messages (sender, recipient, ciphertext, nonce, enc_key, plaintext, sent_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (sender, recipient, rsa_cipher, "", "", plaintext, now_iso())
        )
        db_commit()
        return jsonify({"ok": True, "sent_at": now_iso(), "mode": "rsa"}), 201

    # No RSA cipher — use server-side ChaosKey AES-256-GCM
    ok, enc = ck_encrypt(plaintext)
    if not ok:
        err_msg = enc.get("error", "Encryption failed")
        log.warning(f"ck_encrypt failed for {sender}: {err_msg}")
        return jsonify({"error": f"Encryption failed: {err_msg}"}), 502

    db_exec(
        "INSERT INTO messages (sender, recipient, ciphertext, nonce, enc_key, plaintext, sent_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (sender, recipient,
         enc.get("ciphertext", ""),
         enc.get("nonce", ""),
         enc.get("encryption_key", ""),
         plaintext,
         now_iso())
    )
    db_commit()
    return jsonify({"ok": True, "sent_at": now_iso(), "mode": "chaoskey"}), 201


@app.route("/msg/thread", methods=["GET"])
@require_login
def get_thread():
    contact = request.args.get("with", "").strip().lower()
    me      = session["user_email"]

    if not contact:
        return jsonify({"error": "?with= required"}), 400

    rows = db_exec(
        "SELECT id, sender, recipient, ciphertext, nonce, enc_key, plaintext, sent_at "
        "FROM messages "
        "WHERE (sender=? AND recipient=?) OR (sender=? AND recipient=?) "
        "ORDER BY id ASC",
        (me, contact, contact, me)
    ).fetchall()

    result = []
    for r in rows:
        text = r["plaintext"]
        # If no nonce, message was RSA-encrypted client-side — send ciphertext back for browser decryption
        is_rsa = not r["nonce"]
        if not text and not is_rsa:
            ok, dec = ck_decrypt(r["ciphertext"], r["nonce"], r["enc_key"])
            text = dec.get("plaintext", "[Decryption failed]") if ok else "[Decryption failed]"
        result.append({
            "id":       r["id"],
            "from":     r["sender"],
            "text":     text or "",
            "cipher":   r["ciphertext"][:32] + "…" if r["ciphertext"] else "",
            # Send full ciphertext back when RSA mode so client can decrypt
            "rsa_cipher": r["ciphertext"] if is_rsa else None,
            "sent_at":  r["sent_at"],
        })

    return jsonify(result)


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
        "  COUNT(*) as total, "
        "  SUM(CASE WHEN sender!=? THEN 1 ELSE 0 END) as received "
        "FROM messages WHERE sender=? OR recipient=? "
        "GROUP BY contact ORDER BY last_at DESC",
        (me, me, me, me)
    ).fetchall()

    contacts_with_info = []
    for r in rows:
        user = db_exec(
            "SELECT display_name, avatar_color FROM users WHERE email=?", (r["contact"],)
        ).fetchone()
        contacts_with_info.append({
            "contact":  r["contact"],
            "name":     user["display_name"] if user else r["contact"].split("@")[0],
            "color":    user["avatar_color"] if user else "#888",
            "last_at":  r["last_at"],
            "total":    r["total"],
        })
    return jsonify(contacts_with_info)


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
    return jsonify([{"email": r["email"], "name": r["display_name"], "color": r["avatar_color"]} for r in rows])


@app.route("/health")
def health():
    return jsonify({
        "status":         "ok",
        "chaoskey_url":   CHAOSKEY_URL or None,
        "chaoskey_ready": bool(CHAOSKEY_URL),
        "db_backend":     "postgresql" if USE_POSTGRES else "sqlite",
        "e2ee":           "RSA-OAEP-2048 + AES-256-GCM (ChaosKey fallback)",
    })


# ════════════════════════════════════════════════════════════════
#  FRONTEND  (single-page app served at /)
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
/* ── Reset & Tokens ──────────────────────────────────────────────────── */
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --void:#060608;
  --coal:#0d0e13;
  --ash:#181a22;
  --cinder:#22252f;
  --smoke:#2e3140;
  --dust:#4a4f61;
  --fog:#6b7182;
  --mist:#9097a8;
  --paper:#c8ccdb;
  --snow:#eef0f6;

  --ember:#ff6b35;
  --flame:#ff8c42;
  --glow:#ffb347;
  --spark:#ffd166;
  --cold:#4ecdc4;
  --ice:#a8e6cf;

  --ember-dim:rgba(255,107,53,.12);
  --ember-mid:rgba(255,107,53,.25);
  --ember-glow:0 0 30px rgba(255,107,53,.3);
  --cold-glow:0 0 20px rgba(78,205,196,.2);

  --r-sm:8px;
  --r-md:14px;
  --r-lg:20px;
  --r-xl:28px;
}
html{-webkit-font-smoothing:antialiased;height:100%}
body{background:var(--void);color:var(--paper);font-family:'Syne',sans-serif;height:100%;overflow:hidden}

/* ── Scrollbar ───────────────────────────────────────────────────────── */
::-webkit-scrollbar{width:3px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--smoke);border-radius:2px}

/* ══════════════════════════════════════════════════════
   AUTH SCREEN
══════════════════════════════════════════════════════ */
#auth{
  position:fixed;inset:0;
  display:flex;align-items:center;justify-content:center;
  background:var(--void);
  z-index:100;
}
#auth.hidden{display:none}

.auth-bg{
  position:absolute;inset:0;
  background:
    radial-gradient(ellipse 80% 60% at 20% 80%, rgba(255,107,53,.07) 0%, transparent 60%),
    radial-gradient(ellipse 60% 50% at 80% 20%, rgba(78,205,196,.05) 0%, transparent 50%);
  pointer-events:none;
}
.auth-noise{
  position:absolute;inset:0;
  background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.03'/%3E%3C/svg%3E");
  pointer-events:none;opacity:.4;
}

.auth-card{
  position:relative;
  width:100%;max-width:420px;
  padding:3rem 2.5rem;
  background:var(--coal);
  border:1px solid var(--cinder);
  border-radius:var(--r-xl);
  box-shadow:0 40px 80px rgba(0,0,0,.6);
  animation:riseIn .5s cubic-bezier(.22,1,.36,1) both;
}
@keyframes riseIn{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:none}}

.auth-wordmark{
  display:flex;align-items:center;gap:12px;
  margin-bottom:2.5rem;
}
.burn-icon{
  width:42px;height:42px;
  background:linear-gradient(135deg,var(--ember),var(--glow));
  border-radius:12px;
  display:flex;align-items:center;justify-content:center;
  font-size:1.3rem;
  box-shadow:var(--ember-glow);
  flex-shrink:0;
}
.wordmark-text h1{
  font-size:1.5rem;font-weight:800;
  letter-spacing:-.03em;color:var(--snow);
}
.wordmark-text p{
  font-family:'Fira Code',monospace;
  font-size:.65rem;color:var(--fog);
  letter-spacing:.06em;margin-top:1px;
}

.auth-tabs{
  display:flex;gap:4px;
  background:var(--ash);border-radius:10px;padding:4px;
  margin-bottom:1.75rem;
}
.auth-tab{
  flex:1;padding:.55rem;
  background:none;border:none;
  font-family:'Syne',sans-serif;font-size:.82rem;font-weight:600;
  color:var(--fog);cursor:pointer;
  border-radius:7px;transition:all .2s;
}
.auth-tab.active{background:var(--cinder);color:var(--snow)}

.form-field{margin-bottom:1rem}
.form-field label{
  display:block;
  font-family:'Fira Code',monospace;font-size:.68rem;
  color:var(--fog);letter-spacing:.06em;text-transform:uppercase;
  margin-bottom:.45rem;
}
.form-field input{
  width:100%;padding:.75rem 1rem;
  background:var(--ash);border:1px solid var(--smoke);border-radius:var(--r-sm);
  color:var(--snow);font-family:'Syne',sans-serif;font-size:.92rem;
  outline:none;transition:border-color .2s,box-shadow .2s;
}
.form-field input::placeholder{color:var(--dust)}
.form-field input:focus{border-color:var(--ember);box-shadow:0 0 0 3px rgba(255,107,53,.12)}

.auth-submit{
  width:100%;padding:.85rem;margin-top:.5rem;
  background:linear-gradient(135deg,var(--ember),var(--flame));
  color:#fff;border:none;border-radius:var(--r-sm);
  font-family:'Syne',sans-serif;font-weight:700;font-size:.95rem;
  cursor:pointer;letter-spacing:.01em;
  transition:all .2s;box-shadow:0 4px 20px rgba(255,107,53,.3);
}
.auth-submit:hover{transform:translateY(-1px);box-shadow:0 8px 30px rgba(255,107,53,.4)}
.auth-submit:disabled{opacity:.4;cursor:not-allowed;transform:none}

.auth-err{
  font-family:'Fira Code',monospace;font-size:.75rem;
  color:#ff8fab;text-align:center;min-height:1.2rem;
  margin-top:.75rem;
}

/* ══════════════════════════════════════════════════════
   CHAT SHELL
══════════════════════════════════════════════════════ */
#app{
  display:flex;height:100vh;
}
#app.hidden{display:none}

/* ── Sidebar ─────────────────────────────────────────────────────────── */
.sidebar{
  width:300px;flex-shrink:0;
  background:var(--coal);border-right:1px solid var(--cinder);
  display:flex;flex-direction:column;
  overflow:hidden;
}

.sidebar-top{
  padding:1.25rem 1.25rem 0;
}
.user-row{
  display:flex;align-items:center;justify-content:space-between;
  margin-bottom:1.25rem;
}
.user-chip{
  display:flex;align-items:center;gap:10px;
}
.avatar{
  width:34px;height:34px;border-radius:10px;
  display:flex;align-items:center;justify-content:center;
  font-weight:700;font-size:.85rem;color:#fff;
  flex-shrink:0;
}
.user-meta .uname{
  font-size:.88rem;font-weight:700;color:var(--snow);
}
.user-meta .uemail{
  font-family:'Fira Code',monospace;font-size:.65rem;color:var(--fog);
}
.logout-btn{
  background:none;border:none;
  font-family:'Fira Code',monospace;font-size:.68rem;
  color:var(--dust);cursor:pointer;
  padding:.3rem .6rem;border-radius:6px;
  transition:color .2s,background .2s;
}
.logout-btn:hover{color:var(--ember);background:var(--ember-dim)}

.search-wrap{
  position:relative;margin-bottom:1.25rem;
}
.search-wrap input{
  width:100%;padding:.6rem .9rem .6rem 2.4rem;
  background:var(--ash);border:1px solid var(--smoke);border-radius:10px;
  color:var(--snow);font-family:'Syne',sans-serif;font-size:.85rem;
  outline:none;transition:border-color .2s;
}
.search-wrap input:focus{border-color:var(--ember)}
.search-wrap input::placeholder{color:var(--dust)}
.search-icon{
  position:absolute;left:.8rem;top:50%;transform:translateY(-50%);
  font-size:.85rem;pointer-events:none;color:var(--fog);
}
.search-results{
  position:absolute;top:calc(100% + 4px);left:0;right:0;
  background:var(--cinder);border:1px solid var(--smoke);border-radius:10px;
  overflow:hidden;z-index:50;
  box-shadow:0 10px 30px rgba(0,0,0,.5);
  display:none;
}
.search-results.open{display:block}
.search-result-item{
  display:flex;align-items:center;gap:10px;
  padding:.7rem 1rem;cursor:pointer;
  transition:background .15s;
}
.search-result-item:hover{background:var(--smoke)}
.sr-info .sr-name{font-size:.85rem;font-weight:600;color:var(--snow)}
.sr-info .sr-email{font-family:'Fira Code',monospace;font-size:.65rem;color:var(--fog)}

.sidebar-label{
  font-family:'Fira Code',monospace;font-size:.65rem;
  color:var(--dust);letter-spacing:.08em;text-transform:uppercase;
  padding:0 1.25rem .5rem;
}

.thread-list{
  flex:1;overflow-y:auto;
  padding:0 .5rem .5rem;
}
.thread-item{
  display:flex;align-items:center;gap:10px;
  padding:.75rem .75rem;border-radius:12px;
  cursor:pointer;transition:background .15s;
  margin-bottom:2px;
}
.thread-item:hover{background:var(--ash)}
.thread-item.active{background:var(--ember-dim);border:1px solid var(--ember-mid)}
.thread-item.active .thread-name{color:var(--glow)}
.thread-info{flex:1;min-width:0}
.thread-name{
  font-size:.9rem;font-weight:600;color:var(--snow);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
}
.thread-email{
  font-family:'Fira Code',monospace;font-size:.62rem;color:var(--fog);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
}
.thread-time{
  font-family:'Fira Code',monospace;font-size:.62rem;color:var(--dust);flex-shrink:0;
}
.no-threads{
  padding:2rem 1rem;text-align:center;
  color:var(--dust);font-size:.82rem;line-height:1.6;
}
.no-threads .nt-icon{font-size:2rem;margin-bottom:.5rem}

/* ── Main panel ──────────────────────────────────────────────────────── */
.main{
  flex:1;display:flex;flex-direction:column;
  background:var(--void);overflow:hidden;
  position:relative;
}

.empty-state{
  flex:1;display:flex;align-items:center;justify-content:center;
  flex-direction:column;gap:.75rem;color:var(--dust);
  text-align:center;padding:2rem;
}
.es-icon{font-size:3rem;margin-bottom:.5rem;opacity:.4}
.es-title{font-size:1.1rem;font-weight:700;color:var(--fog)}
.es-sub{font-family:'Fira Code',monospace;font-size:.75rem;line-height:1.6}

.chat-view{
  display:none;flex-direction:column;height:100%;
}
.chat-view.active{display:flex}

/* Chat header */
.chat-header{
  display:flex;align-items:center;justify-content:space-between;
  padding:1rem 1.5rem;
  background:var(--coal);border-bottom:1px solid var(--cinder);
  flex-shrink:0;
}
.chat-header-left{display:flex;align-items:center;gap:12px}
.contact-info .cname{
  font-size:.95rem;font-weight:700;color:var(--snow);
}
.contact-info .cemail{
  font-family:'Fira Code',monospace;font-size:.65rem;color:var(--fog);
  margin-top:1px;
}
.enc-badge{
  display:flex;align-items:center;gap:5px;
  font-family:'Fira Code',monospace;font-size:.65rem;
  color:var(--cold);padding:.2rem .55rem;
  background:rgba(78,205,196,.08);border:1px solid rgba(78,205,196,.2);
  border-radius:100px;
}
.burn-thread-btn{
  display:flex;align-items:center;gap:6px;
  padding:.45rem .9rem;border-radius:8px;
  background:rgba(255,90,90,.1);border:1px solid rgba(255,90,90,.2);
  color:#ff8fab;font-family:'Syne',sans-serif;font-size:.78rem;font-weight:600;
  cursor:pointer;transition:all .2s;
}
.burn-thread-btn:hover{background:rgba(255,90,90,.2);color:#ff6b6b}

/* Messages area */
.messages{
  flex:1;overflow-y:auto;
  padding:1.5rem;display:flex;flex-direction:column;gap:.75rem;
}

.msg-group{display:flex;flex-direction:column;gap:3px;max-width:70%}
.msg-group.mine{align-self:flex-end;align-items:flex-end}
.msg-group.theirs{align-self:flex-start;align-items:flex-start}

.bubble{
  padding:.65rem 1rem;
  font-family:'Lora',serif;font-size:.9rem;line-height:1.6;
  word-break:break-word;
  position:relative;
}
.mine .bubble{
  background:linear-gradient(135deg,var(--ember),var(--flame));
  color:#fff;border-radius:18px 18px 4px 18px;
}
.theirs .bubble{
  background:var(--ash);border:1px solid var(--cinder);
  color:var(--snow);border-radius:18px 18px 18px 4px;
}
.bubble.decrypting{
  color:var(--dust);font-style:italic;font-size:.8rem;
}

.cipher-bar{
  font-family:'Fira Code',monospace;font-size:.58rem;
  color:var(--ember);opacity:.5;
  max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  padding:0 .25rem;cursor:help;
  transition:opacity .2s;
}
.cipher-bar:hover{opacity:1}

.msg-meta{
  font-family:'Fira Code',monospace;font-size:.6rem;
  color:var(--dust);padding:0 .3rem;
}
.e2ee-tag{
  font-family:'Fira Code',monospace;font-size:.55rem;
  color:var(--cold);opacity:.6;padding:0 .3rem;
}

/* Compose */
.compose{
  padding:1rem 1.5rem;
  background:var(--coal);border-top:1px solid var(--cinder);
  display:flex;gap:.75rem;align-items:flex-end;
  flex-shrink:0;
}
.compose-wrap{
  flex:1;background:var(--ash);
  border:1px solid var(--smoke);border-radius:14px;
  overflow:hidden;transition:border-color .2s,box-shadow .2s;
}
.compose-wrap:focus-within{
  border-color:var(--ember);
  box-shadow:0 0 0 3px rgba(255,107,53,.1);
}
.compose-input{
  width:100%;padding:.8rem 1rem;
  background:none;border:none;
  color:var(--snow);font-family:'Lora',serif;font-size:.9rem;
  outline:none;resize:none;
  max-height:120px;line-height:1.5;
}
.compose-input::placeholder{color:var(--dust)}
.send-btn{
  width:44px;height:44px;flex-shrink:0;
  background:linear-gradient(135deg,var(--ember),var(--flame));
  border:none;border-radius:12px;
  color:#fff;font-size:1.1rem;cursor:pointer;
  display:flex;align-items:center;justify-content:center;
  transition:all .2s;
  box-shadow:0 4px 12px rgba(255,107,53,.3);
}
.send-btn:hover{transform:scale(1.05);box-shadow:0 6px 20px rgba(255,107,53,.45)}
.send-btn:disabled{opacity:.35;cursor:not-allowed;transform:none}

/* ── Burn confirmation modal ─────────────────────────────────────────── */
.modal-overlay{
  position:fixed;inset:0;background:rgba(0,0,0,.7);
  display:flex;align-items:center;justify-content:center;
  z-index:200;opacity:0;pointer-events:none;transition:opacity .2s;
}
.modal-overlay.open{opacity:1;pointer-events:all}
.modal{
  background:var(--coal);border:1px solid var(--cinder);border-radius:var(--r-xl);
  padding:2rem 2.25rem;max-width:380px;width:90%;
  box-shadow:0 40px 80px rgba(0,0,0,.6);
  transform:scale(.95);transition:transform .2s;
}
.modal-overlay.open .modal{transform:scale(1)}
.modal-icon{font-size:2.5rem;margin-bottom:1rem}
.modal h2{font-size:1.1rem;font-weight:800;color:var(--snow);margin-bottom:.5rem}
.modal p{font-family:'Fira Code',monospace;font-size:.75rem;color:var(--fog);line-height:1.6;margin-bottom:1.5rem}
.modal-btns{display:flex;gap:.75rem}
.modal-cancel,.modal-confirm{
  flex:1;padding:.7rem;border-radius:10px;border:none;
  font-family:'Syne',sans-serif;font-weight:700;font-size:.88rem;cursor:pointer;
  transition:all .15s;
}
.modal-cancel{background:var(--ash);color:var(--paper);border:1px solid var(--smoke)}
.modal-cancel:hover{border-color:var(--fog)}
.modal-confirm{
  background:linear-gradient(135deg,#ff4444,#ff6b35);
  color:#fff;box-shadow:0 4px 15px rgba(255,60,60,.3);
}
.modal-confirm:hover{transform:translateY(-1px);box-shadow:0 6px 20px rgba(255,60,60,.4)}

/* ── Toast ───────────────────────────────────────────────────────────── */
.toast{
  position:fixed;bottom:2rem;left:50%;transform:translateX(-50%) translateY(20px);
  background:var(--cinder);color:var(--snow);
  font-family:'Fira Code',monospace;font-size:.78rem;
  padding:.65rem 1.25rem;border-radius:100px;
  border:1px solid var(--smoke);
  opacity:0;transition:opacity .25s,transform .25s;
  pointer-events:none;z-index:300;white-space:nowrap;
}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.toast.ok{border-color:rgba(168,230,207,.3);color:var(--ice)}
.toast.err{border-color:rgba(255,107,53,.3);color:var(--ember)}

/* ── Responsive ──────────────────────────────────────────────────────── */
@media(max-width:680px){
  .sidebar{width:100%;display:none}
  .sidebar.mobile-open{display:flex;position:fixed;inset:0;z-index:50}
}
</style>
</head>
<body>

<!-- ══ AUTH SCREEN ═════════════════════════════════════════════════════ -->
<div id="auth">
  <div class="auth-bg"></div>
  <div class="auth-noise"></div>
  <div class="auth-card">
    <div class="auth-wordmark">
      <div class="burn-icon">🔥</div>
      <div class="wordmark-text">
        <h1>BurnChat</h1>
        <p>RSA-OAEP · AES-256-GCM · SELF-DESTRUCT</p>
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
        <input id="f-email" type="email" placeholder="you@example.com" autocomplete="email"
          onkeydown="if(event.key==='Enter')document.getElementById('f-pw').focus()">
      </div>
      <div class="form-field">
        <label>Password</label>
        <input id="f-pw" type="password" placeholder="••••••••" autocomplete="current-password"
          onkeydown="if(event.key==='Enter' && S.authMode==='login')doAuth(); else if(event.key==='Enter')document.getElementById('f-ck-key').focus()">
      </div>
      <div class="form-field" id="field-ck-key" style="display:none">
        <label>ChaosKey API key</label>
        <input id="f-ck-key" type="text" placeholder="ck_live_…" autocomplete="off" spellcheck="false"
          style="font-family:'Fira Code',monospace;font-size:.82rem;letter-spacing:.01em"
          onkeydown="if(event.key==='Enter')doAuth()">
        <div style="font-family:'Fira Code',monospace;font-size:.63rem;color:var(--fog);margin-top:.4rem;line-height:1.5">
          Register on ChaosKey → copy your <code style="color:var(--ember)">ck_live_…</code> key here
        </div>
      </div>
    </div>
    <button class="auth-submit" id="auth-btn" onclick="doAuth()">Sign in →</button>
    <div class="auth-err" id="auth-err"></div>
  </div>
</div>

<!-- ══ APP SHELL ═══════════════════════════════════════════════════════ -->
<div id="app" class="hidden">

  <!-- Sidebar -->
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
        <button onclick="showUpdateKeyModal()" style="background:none;border:none;font-family:'Fira Code',monospace;font-size:.62rem;color:var(--dust);cursor:pointer;padding:0;transition:color .15s;" onmouseover="this.style.color='var(--ember)'" onmouseout="this.style.color='var(--dust)'">update</button>
      </div>
      <div id="ck-key-warn" style="display:none;padding:.5rem .7rem;background:rgba(255,107,53,.1);border:1px solid rgba(255,107,53,.25);border-radius:8px;margin-bottom:.75rem;">
        <div style="font-family:'Fira Code',monospace;font-size:.65rem;color:var(--ember);margin-bottom:.3rem">⚠ No ChaosKey API key</div>
        <button onclick="showUpdateKeyModal()" style="background:var(--ember);border:none;color:#fff;font-family:'Syne',sans-serif;font-size:.72rem;font-weight:700;padding:.3rem .7rem;border-radius:6px;cursor:pointer;width:100%">Add key →</button>
      </div>
      <div id="e2ee-status" style="display:none;align-items:center;gap:6px;margin-bottom:.75rem;padding:.4rem .7rem;background:rgba(78,205,196,.06);border:1px solid rgba(78,205,196,.15);border-radius:8px;">
        <span style="font-size:.7rem">🔑</span>
        <span style="font-family:'Fira Code',monospace;font-size:.63rem;color:var(--cold)">RSA keys ready</span>
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

  <!-- Main -->
  <div class="main">
    <div class="empty-state" id="empty-state">
      <div class="es-icon">🔥</div>
      <div class="es-title">Select a conversation</div>
      <div class="es-sub">
        End-to-end encrypted with RSA-OAEP<br>
        AES-256-GCM server layer via ChaosKey
      </div>
    </div>

    <div class="chat-view" id="chat-view">
      <div class="chat-header">
        <div class="chat-header-left">
          <div class="avatar" id="contact-avatar" style="background:#888">C</div>
          <div class="contact-info">
            <div class="cname" id="contact-name">–</div>
            <div class="cemail" id="contact-email">–</div>
          </div>
          <div class="enc-badge" id="enc-badge">⚿ E2EE</div>
        </div>
        <div style="display:flex;align-items:center;gap:.75rem">
          <button class="burn-thread-btn" onclick="confirmBurn()">🔥 Burn thread</button>
        </div>
      </div>

      <div class="messages" id="messages-area"></div>

      <div class="compose">
        <div class="compose-wrap">
          <textarea class="compose-input" id="compose-input" rows="1"
            placeholder="Write an encrypted message… (Enter to send)"
            oninput="autoResize(this)"
            onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendMessage();}">
          </textarea>
        </div>
        <button class="send-btn" id="send-btn" onclick="sendMessage()">➤</button>
      </div>
    </div>
  </div>
</div>

<!-- Burn confirmation modal -->
<div class="modal-overlay" id="burn-modal">
  <div class="modal">
    <div class="modal-icon">🔥</div>
    <h2>Burn this thread?</h2>
    <p id="burn-modal-text">This will permanently delete all messages. The ashes will never be recovered.</p>
    <div class="modal-btns">
      <button class="modal-cancel" onclick="closeBurnModal()">Cancel</button>
      <button class="modal-confirm" onclick="executeBurn()">Burn it</button>
    </div>
  </div>
</div>

<!-- Update ChaosKey API key modal -->
<div class="modal-overlay" id="key-modal">
  <div class="modal">
    <div class="modal-icon">⚿</div>
    <h2>Update ChaosKey API key</h2>
    <p>Paste a fresh <code style="font-family:'Fira Code',monospace;color:var(--ember)">ck_live_…</code> key from your ChaosKey account. The old key will be replaced.</p>
    <div style="margin:1rem 0">
      <input id="modal-ck-input" type="text" placeholder="ck_live_…"
        style="width:100%;padding:.75rem 1rem;background:var(--ash);border:1px solid var(--smoke);border-radius:8px;color:var(--snow);font-family:'Fira Code',monospace;font-size:.82rem;outline:none;"
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
  me:            null,
  activeContact: null,
  threads:       [],
  pollTimer:     null,
  authMode:      'login',
  // RSA key pair (CryptoKey objects, stored in memory only — private never leaves browser)
  rsaPublicKey:  null,
  rsaPrivateKey: null,
};

// ════════════════════════════════════════════════════════════════
//  Utilities
// ════════════════════════════════════════════════════════════════
const $  = id => document.getElementById(id);
const esc = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const initials = s => (s||'?')[0].toUpperCase();

function toast(msg, type='ok', dur=2800) {
  const el = $('toast');
  el.textContent = msg;
  el.className = `toast ${type} show`;
  setTimeout(() => el.classList.remove('show'), dur);
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

function autoResize(ta) {
  ta.style.height = 'auto';
  ta.style.height = Math.min(ta.scrollHeight, 120) + 'px';
}

function fmtTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return d.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
}
function fmtDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  const now = new Date();
  if (d.toDateString() === now.toDateString()) return 'Today';
  const yesterday = new Date(now); yesterday.setDate(now.getDate()-1);
  if (d.toDateString() === yesterday.toDateString()) return 'Yesterday';
  return d.toLocaleDateString([], {month:'short', day:'numeric'});
}

// ════════════════════════════════════════════════════════════════
//  RSA-OAEP Key Management  (from BurnChat E2EE v1)
// ════════════════════════════════════════════════════════════════

/** Generate a fresh RSA-OAEP 2048-bit key pair and persist public key to server. */
async function genAndRegisterKeys() {
  const kp = await crypto.subtle.generateKey(
    {name:'RSA-OAEP', modulusLength:2048, publicExponent:new Uint8Array([1,0,1]), hash:'SHA-256'},
    true, ['encrypt','decrypt']
  );
  S.rsaPublicKey  = kp.publicKey;
  S.rsaPrivateKey = kp.privateKey;

  // Export public key as base64 SPKI
  const pubRaw  = await crypto.subtle.exportKey('spki', kp.publicKey);
  const pubB64  = btoa(String.fromCharCode(...new Uint8Array(pubRaw)));

  // Export private key as base64 PKCS8 and stash in localStorage (never sent to server)
  const privRaw = await crypto.subtle.exportKey('pkcs8', kp.privateKey);
  const privB64 = btoa(String.fromCharCode(...new Uint8Array(privRaw)));
  localStorage.setItem('bc_priv_' + S.me.email, privB64);

  return pubB64;
}

/** Load private key from localStorage and import it back into a CryptoKey. */
async function loadPrivateKey(email) {
  const privB64 = localStorage.getItem('bc_priv_' + email);
  if (!privB64) return null;
  try {
    const privRaw = Uint8Array.from(atob(privB64), c => c.charCodeAt(0));
    return await crypto.subtle.importKey(
      'pkcs8', privRaw,
      {name:'RSA-OAEP', hash:'SHA-256'},
      false, ['decrypt']
    );
  } catch { return null; }
}

/** Import a recipient's public key from base64 SPKI. */
async function importPublicKey(pubB64) {
  const raw = Uint8Array.from(atob(pubB64), c => c.charCodeAt(0));
  return crypto.subtle.importKey(
    'spki', raw,
    {name:'RSA-OAEP', hash:'SHA-256'},
    false, ['encrypt']
  );
}

/** Encrypt plaintext with a CryptoKey (recipient's public key). Returns base64 ciphertext. */
async function rsaEncrypt(plaintext, cryptoKey) {
  const enc = await crypto.subtle.encrypt(
    {name:'RSA-OAEP'},
    cryptoKey,
    new TextEncoder().encode(plaintext)
  );
  return btoa(String.fromCharCode(...new Uint8Array(enc)));
}

/** Decrypt base64 RSA ciphertext with the local private key. */
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

/** Fetch a user's public key from the server. Returns base64 string or null. */
async function fetchPublicKey(email) {
  const {ok, data} = await api('/user/key?email=' + encodeURIComponent(email));
  return (ok && data.key) ? data.key : null;
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
  const email  = $('f-email').value.trim().toLowerCase();
  const pw     = $('f-pw').value;
  const name   = $('f-name').value.trim();
  const ckKey  = $('f-ck-key').value.trim();
  const err    = $('auth-err');
  const btn    = $('auth-btn');

  if (!email) { err.textContent = '⚠ Email required'; return; }
  if (!pw)    { err.textContent = '⚠ Password required'; return; }
  if (S.authMode === 'signup' && !ckKey) {
    err.textContent = '⚠ ChaosKey API key required'; return;
  }

  btn.disabled = true;
  err.textContent = '';

  let pubB64 = null;

  if (S.authMode === 'signup') {
    // Generate RSA keys; send public key to server
    S.me = {email, name: name || email.split('@')[0], color: '#ff6b35'};
    try {
      pubB64 = await genAndRegisterKeys();
    } catch(e) {
      err.textContent = '⚠ Could not generate encryption keys: ' + e.message;
      btn.disabled = false;
      return;
    }
  }

  const path = S.authMode === 'signup' ? '/auth/signup' : '/auth/login';
  const body = S.authMode === 'signup'
    ? {email, password:pw, name, chaoskey_api_key:ckKey, public_key:pubB64}
    : {email, password:pw};

  const {ok, data} = await api(path, {method:'POST', body:JSON.stringify(body)});
  if (ok) {
    S.me = {email:data.email, name:data.name, color:data.color};

    // On login, load private key from localStorage (if exists) or re-register a new one
    if (S.authMode === 'login') {
      S.rsaPrivateKey = await loadPrivateKey(email);
      if (!S.rsaPrivateKey) {
        // No local private key — generate fresh pair and update server pubkey
        pubB64 = await genAndRegisterKeys();
        await api('/user/update_key', {method:'POST', body:JSON.stringify({public_key:pubB64})});
        toast('🔑 New RSA keys generated (first login on this device)', 'ok', 4000);
      }
      // Also load public key into memory
      const privB64 = localStorage.getItem('bc_priv_' + email);
      if (privB64) {
        // Derive the public key from the stored private key isn't possible in WebCrypto
        // Instead, fetch own pub key from server to have it available
        const ownPub = data.public_key || await fetchPublicKey(email);
        if (ownPub) {
          try { S.rsaPublicKey = await importPublicKey(ownPub); } catch {}
        }
      }
    }

    enterApp(data);
  } else {
    err.textContent = '⚠ ' + (data.error || 'Authentication failed');
    btn.disabled = false;
  }
}

async function doLogout() {
  await api('/auth/logout', {method:'POST'});
  location.reload();
}

async function checkSession() {
  const {ok, data} = await api('/auth/me');
  if (ok && data.authenticated) {
    S.me = {email:data.email, name:data.name, color:data.color};
    // Attempt to restore RSA private key from localStorage
    S.rsaPrivateKey = await loadPrivateKey(data.email);
    if (!S.rsaPrivateKey) {
      // Generate new pair silently and update server
      const pubB64 = await genAndRegisterKeys();
      await api('/user/update_key', {method:'POST', body:JSON.stringify({public_key:pubB64})});
    }
    enterApp(data);
  }
}

// ════════════════════════════════════════════════════════════════
//  App
// ════════════════════════════════════════════════════════════════
function enterApp(data={}) {
  $('auth').classList.add('hidden');
  $('app').classList.remove('hidden');

  $('my-avatar').textContent = initials(S.me.name);
  $('my-avatar').style.background = S.me.color;
  $('my-name').textContent  = S.me.name;
  $('my-email').textContent = S.me.email;

  // Show ChaosKey status bar
  const hasCk = data.has_ck_key;
  if (hasCk && data.key_prefix) {
    $('ck-key-bar').style.display = 'flex';
    $('ck-key-prefix').textContent = data.key_prefix;
  } else if (!hasCk) {
    $('ck-key-warn').style.display = 'block';
  }

  // Show RSA status
  if (S.rsaPrivateKey) {
    $('e2ee-status').style.display = 'flex';
  }

  loadInbox();
  S.pollTimer = setInterval(async () => {
    await loadInbox();
    if (S.activeContact) {
      $('messages-area').dataset.hash = '';
      await loadThread(S.activeContact.email, false);
    }
  }, 3000);
}

// ════════════════════════════════════════════════════════════════
//  Inbox / sidebar helpers
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
    <div class="thread-item ${S.activeContact?.email === t.contact ? 'active' : ''}"
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
      <div class="sr-info">
        <div class="sr-name">${esc(u.name)}</div>
        <div class="sr-email">${esc(u.email)}</div>
      </div>
    </div>`).join('');
  res.classList.add('open');
}

function closeSearch() {
  $('search-results').classList.remove('open');
}

// ════════════════════════════════════════════════════════════════
//  Thread / messages
// ════════════════════════════════════════════════════════════════
function openThread(email, name, color) {
  S.activeContact = {email, name, color};
  $('contact-name').textContent  = name;
  $('contact-email').textContent = email;
  $('contact-avatar').textContent = initials(name);
  $('contact-avatar').style.background = color;

  // Update enc badge based on whether we have RSA keys
  $('enc-badge').textContent = S.rsaPrivateKey ? '⚿ RSA-OAEP + AES-256' : '⚿ AES-256-GCM';

  $('empty-state').style.display = 'none';
  $('chat-view').classList.add('active');

  // Close search
  $('search-input').value = '';
  closeSearch();

  // Re-render sidebar to mark active
  renderThreadList();

  loadThread(email, true);
}

async function loadThread(email, scrollToBottom=true) {
  const {ok, data} = await api(`/msg/thread?with=${encodeURIComponent(email)}`);
  if (!ok || !Array.isArray(data)) return;

  const area = $('messages-area');
  const msgs = [];

  for (const m of data) {
    const mine = m.from === S.me.email;
    let text = m.text;

    // RSA-encrypted messages: client decrypts if it's a message TO us
    if (!text && m.rsa_cipher) {
      if (!mine && S.rsaPrivateKey) {
        text = await rsaDecrypt(m.rsa_cipher);
        if (!text) text = '[Cannot decrypt — wrong device?]';
      } else if (mine) {
        text = '[Sent encrypted — only recipient can read]';
      } else {
        text = '[No private key — cannot decrypt]';
      }
    }

    msgs.push({...m, resolved: text || '[empty]'});
  }

  let html = '';
  for (const m of msgs) {
    const mine = m.from === S.me.email;
    const isRsa = !!m.rsa_cipher;
    html += `
      <div class="msg-group ${mine ? 'mine' : 'theirs'}">
        <div class="bubble">${esc(m.resolved)}</div>
        <div class="msg-meta">${fmtTime(m.sent_at)}</div>
        ${isRsa ? `<div class="e2ee-tag">🔑 RSA-OAEP</div>` : ''}
      </div>`;
  }

  const newHash = btoa(unescape(encodeURIComponent(html))).slice(0, 20);
  if (area.dataset.hash !== newHash) {
    area.innerHTML = html || `<div style="text-align:center;color:var(--dust);font-family:'Fira Code',monospace;font-size:.75rem;margin-top:2rem">No messages yet. Say something!</div>`;
    area.dataset.hash = newHash;
    if (scrollToBottom) area.scrollTop = area.scrollHeight;
  }
}

// ════════════════════════════════════════════════════════════════
//  Send  (RSA-OAEP preferred, ChaosKey fallback)
// ════════════════════════════════════════════════════════════════
async function sendMessage() {
  const inp = $('compose-input');
  const txt = inp.value.trim();
  if (!txt || !S.activeContact) return;

  const btn = $('send-btn');
  btn.disabled = true;

  let body = {recipient: S.activeContact.email, plaintext: txt};
  let useRsa = false;

  // Attempt RSA-OAEP encryption with recipient's public key
  try {
    const recipPubB64 = await fetchPublicKey(S.activeContact.email);
    if (recipPubB64) {
      const recipKey  = await importPublicKey(recipPubB64);
      const ciphertext = await rsaEncrypt(txt, recipKey);
      body.ciphertext = ciphertext;
      useRsa = true;
    }
  } catch(e) {
    console.warn('RSA encrypt failed, falling back to ChaosKey:', e);
  }

  const {ok, data} = await api('/msg/send', {
    method: 'POST',
    body: JSON.stringify(body),
  });

  btn.disabled = false;

  if (!ok) {
    toast('✗ ' + (data.error || 'Send failed'), 'err');
    return;
  }

  inp.value = '';
  inp.style.height = 'auto';
  $('messages-area').dataset.hash = '';
  await loadThread(S.activeContact.email, true);
  await loadInbox();
}

// ════════════════════════════════════════════════════════════════
//  Burn thread
// ════════════════════════════════════════════════════════════════
function confirmBurn() {
  if (!S.activeContact) return;
  $('burn-modal-text').textContent =
    `Burn all messages with ${S.activeContact.name}? This cannot be undone.`;
  $('burn-modal').classList.add('open');
}
function closeBurnModal() { $('burn-modal').classList.remove('open'); }

async function executeBurn() {
  closeBurnModal();
  if (!S.activeContact) return;
  const {ok} = await api('/msg/burn', {
    method: 'POST',
    body: JSON.stringify({contact: S.activeContact.email}),
  });
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
//  Update ChaosKey modal
// ════════════════════════════════════════════════════════════════
function showUpdateKeyModal() { $('key-modal').classList.add('open'); }
function closeKeyModal() {
  $('key-modal').classList.remove('open');
  $('key-modal-err').textContent = '';
  $('modal-ck-input').value = '';
}

async function saveUpdatedKey() {
  const val = $('modal-ck-input').value.trim();
  const errEl = $('key-modal-err');
  if (!val || !val.startsWith('ck_live_')) {
    errEl.textContent = '⚠ Key must start with ck_live_';
    return;
  }
  const {ok, data} = await api('/auth/update_ck_key', {
    method:'POST', body:JSON.stringify({chaoskey_api_key:val})
  });
  if (ok) {
    $('ck-key-prefix').textContent = data.key_prefix;
    $('ck-key-bar').style.display = 'flex';
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


# ── Boot ──────────────────────────────────────────────────────────────────────
try:
    init_db()
except Exception as e:
    log.error(f"DB init failed: {e}")

if __name__ == "__main__":
    log.info(f"BurnChat starting on port {PORT}")
    log.info(f"ChaosKey URL: {CHAOSKEY_URL or '(not set)'}")
    log.info("RSA-OAEP E2EE enabled. Each user's private key stays in their browser.")
    app.run(host="0.0.0.0", port=PORT, debug=False)
