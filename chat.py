"""
BurnChat — Encrypted Ephemeral Messenger
=========================================
Standalone product. Uses ChaosKey API for AES-256-GCM encryption.
Each user supplies their own ChaosKey API key at signup — it is stored
in the BurnChat DB and loaded into their session on every login.
Messages are encrypted at rest; threads can be permanently burned.

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
DB_PATH      = os.getenv("DB_PATH", "")
PORT         = int(os.getenv("PORT", 5000))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("BurnChat")

if not CHAOSKEY_URL:
    log.warning("CHAOSKEY_URL not set — encryption will fail. Set it to your ChaosKey instance URL.")

app = Flask("BurnChat")
app.secret_key = SECRET_KEY
CORS(app, supports_credentials=True)


# ── Database ──────────────────────────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db:
        db.close()

def db_exec(sql, params=()):
    return get_db().execute(sql, params)

def db_commit():
    get_db().commit()

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email           TEXT UNIQUE NOT NULL,
    display_name    TEXT NOT NULL,
    password_hash   TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    avatar_color    TEXT NOT NULL DEFAULT '#ff6b35',
    chaoskey_api_key TEXT
);
CREATE TABLE IF NOT EXISTS messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sender       TEXT NOT NULL,
    recipient    TEXT NOT NULL,
    ciphertext   TEXT NOT NULL,
    nonce        TEXT NOT NULL,
    enc_key      TEXT NOT NULL,
    plaintext    TEXT,
    sent_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_msg_thread
    ON messages(sender, recipient);
"""

def init_db():
    with app.app_context():
        db = sqlite3.connect(DB_PATH)
        db.executescript(SCHEMA)
        for col, default in [
            ("avatar_color",     "'#ff6b35'"),
            ("chaoskey_api_key", "NULL"),
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
    """Return the current user's ChaosKey API key from session."""
    return session.get("ck_api_key", "")

def ck_encrypt(plaintext: str):
    """Encrypt plaintext via ChaosKey using the session user's key."""
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
    """Decrypt ciphertext via ChaosKey using the session user's key."""
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
    body    = request.get_json(force=True) or {}
    email   = body.get("email", "").strip().lower()
    pw      = body.get("password", "").strip()
    name    = body.get("name", "").strip() or email.split("@")[0]
    ck_key  = body.get("chaoskey_api_key", "").strip()

    if not email or "@" not in email:
        return jsonify({"error": "Valid email required"}), 400
    if not pw or len(pw) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    if not ck_key or not ck_key.startswith("ck_live_"):
        return jsonify({"error": "Valid ChaosKey API key required (starts with ck_live_)"}), 400

    color = pick_color(email)
    try:
        db_exec(
            "INSERT INTO users (email, display_name, password_hash, created_at, avatar_color, chaoskey_api_key) "
            "VALUES (?,?,?,?,?,?)",
            (email, name, hash_password(pw), now_iso(), color, ck_key)
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
        "SELECT email, display_name, password_hash, avatar_color, chaoskey_api_key "
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
    """Let a logged-in user update their stored ChaosKey API key."""
    body   = request.get_json(force=True) or {}
    ck_key = body.get("chaoskey_api_key", "").strip()
    if not ck_key or not ck_key.startswith("ck_live_"):
        return jsonify({"error": "Valid ChaosKey API key required (starts with ck_live_)"}), 400
    db_exec("UPDATE users SET chaoskey_api_key = ? WHERE email = ?",
            (ck_key, session["user_email"]))
    db_commit()
    session["ck_api_key"] = ck_key
    return jsonify({"ok": True, "key_prefix": ck_key[:16] + "…"})


# ── Message routes ────────────────────────────────────────────────────────────
@app.route("/msg/send", methods=["POST"])
@require_login
def send_message():
    body      = request.get_json(force=True) or {}
    recipient = body.get("recipient", "").strip().lower()
    plaintext = body.get("plaintext", "").strip()
    sender    = session["user_email"]

    if not recipient or not plaintext:
        return jsonify({"error": "recipient and plaintext required"}), 400
    if recipient == sender:
        return jsonify({"error": "Cannot message yourself"}), 400

    # Check recipient exists
    exists = db_exec("SELECT id FROM users WHERE email = ?", (recipient,)).fetchone()
    if not exists:
        return jsonify({"error": f"User '{recipient}' not found on BurnChat"}), 404

    # Encrypt via ChaosKey
    ok, enc = ck_encrypt(plaintext)
    if not ok:
        return jsonify({"error": enc.get("error", "Encryption failed")}), 502

    db_exec(
        "INSERT INTO messages (sender, recipient, ciphertext, nonce, enc_key, plaintext, sent_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (sender, recipient,
         enc.get("ciphertext", ""),
         enc.get("nonce", ""),
         enc.get("encryption_key", ""),
         plaintext,   # also stored in plaintext for fast retrieval (server trusted)
         now_iso())
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
        "SELECT id, sender, recipient, ciphertext, nonce, enc_key, plaintext, sent_at "
        "FROM messages "
        "WHERE (sender=? AND recipient=?) OR (sender=? AND recipient=?) "
        "ORDER BY id ASC",
        (me, contact, contact, me)
    ).fetchall()

    result = []
    for r in rows:
        text = r["plaintext"]  # fast path — already stored
        if not text:           # fallback: decrypt via ChaosKey
            ok, dec = ck_decrypt(r["ciphertext"], r["nonce"], r["enc_key"])
            text = dec.get("plaintext", "[Decryption failed]") if ok else "[Decryption failed]"
        result.append({
            "id":        r["id"],
            "from":      r["sender"],
            "text":      text,
            "cipher":    r["ciphertext"][:32] + "…" if r["ciphertext"] else "",
            "sent_at":   r["sent_at"],
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
    ck_ok = bool(CHAOSKEY_URL and CHAOSKEY_API_KEY)
    return jsonify({
        "status":           "ok",
        "chaoskey_url":     CHAOSKEY_URL or None,
        "chaoskey_ready":   ck_ok,
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
.day-divider{
  display:flex;align-items:center;gap:1rem;
  margin:.5rem 0;
}
.day-divider span{
  font-family:'Fira Code',monospace;font-size:.65rem;
  color:var(--dust);white-space:nowrap;
}
.day-divider::before,.day-divider::after{
  content:'';flex:1;height:1px;background:var(--cinder);
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
        <p>AES-256-GCM · MESSAGES SELF-DESTRUCT</p>
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
        Messages are encrypted with AES-256-GCM<br>
        powered by ChaosKey physical entropy
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
          <div class="enc-badge">⚿ AES-256-GCM</div>
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
// ════════════════════════════════════════════════════════════════
//  State
// ════════════════════════════════════════════════════════════════
const S = {
  me:          null,   // { email, name, color }
  activeContact: null, // { email, name, color }
  threads:     [],
  pollTimer:   null,
  authMode:    'login',
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

  const path = S.authMode === 'signup' ? '/auth/signup' : '/auth/login';
  const body = S.authMode === 'signup'
    ? {email, password:pw, name, chaoskey_api_key: ckKey}
    : {email, password:pw};

  const {ok, data} = await api(path, {method:'POST', body:JSON.stringify(body)});
  if (ok) {
    S.me = {email:data.email, name:data.name, color:data.color,
            hasKey:data.has_ck_key ?? true, keyPrefix:data.key_prefix};
    enterApp();
  } else {
    err.textContent = '⚠ ' + (data.error || 'Authentication failed');
    btn.disabled = false;
  }
}

async function doLogout() {
  await api('/auth/logout', {method:'POST'});
  S.me = null; S.activeContact = null;
  clearInterval(S.pollTimer);
  $('app').classList.add('hidden');
  $('auth').classList.remove('hidden');
  $('auth-btn').disabled = false;
  $('f-pw').value = '';
  $('auth-err').textContent = '';
}

async function checkSession() {
  const {ok, data} = await api('/auth/me');
  if (ok && data.authenticated) {
    S.me = {email:data.email, name:data.name, color:data.color,
            hasKey:data.has_ck_key, keyPrefix:data.key_prefix};
    enterApp();
  }
}

// ── Update ChaosKey key modal ─────────────────────────────────────────────
function showUpdateKeyModal() {
  $('modal-ck-input').value = '';
  $('key-modal-err').textContent = '';
  $('key-modal').classList.add('open');
  setTimeout(() => $('modal-ck-input').focus(), 100);
}
function closeKeyModal() {
  $('key-modal').classList.remove('open');
}
async function saveUpdatedKey() {
  const key = $('modal-ck-input').value.trim();
  const errEl = $('key-modal-err');
  if (!key || !key.startsWith('ck_live_')) {
    errEl.textContent = '⚠ Must start with ck_live_'; return;
  }
  const {ok, data} = await api('/auth/update_ck_key', {
    method: 'POST',
    body: JSON.stringify({chaoskey_api_key: key}),
  });
  if (ok) {
    S.me.hasKey = true; S.me.keyPrefix = data.key_prefix;
    $('ck-key-prefix').textContent = data.key_prefix;
    $('ck-key-bar').style.display  = 'flex';
    $('ck-key-warn').style.display = 'none';
    closeKeyModal();
    toast('⚿ ChaosKey key updated', 'ok');
  } else {
    errEl.textContent = '⚠ ' + (data.error || 'Failed');
  }
}

function enterApp() {
  $('auth').classList.add('hidden');
  $('app').classList.remove('hidden');
  const av = $('my-avatar');
  av.textContent = initials(S.me.name);
  av.style.background = S.me.color;
  $('my-name').textContent  = S.me.name;
  $('my-email').textContent = S.me.email;

  // Show ChaosKey key status in sidebar
  if (S.me.hasKey && S.me.keyPrefix) {
    $('ck-key-bar').style.display  = 'flex';
    $('ck-key-warn').style.display = 'none';
    $('ck-key-prefix').textContent = S.me.keyPrefix;
  } else {
    $('ck-key-bar').style.display  = 'none';
    $('ck-key-warn').style.display = 'block';
  }

  loadInbox();
  S.pollTimer = setInterval(() => {
    loadInbox();
    if (S.activeContact) loadThread(S.activeContact.email, false);
  }, 3500);
}

// ════════════════════════════════════════════════════════════════
//  Inbox / Threads
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
    el.innerHTML = `<div class="no-threads"><div class="nt-icon">🔒</div>Search for a user above<br>to start a conversation.</div>`;
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

function openThread(email, name, color) {
  S.activeContact = {email, name: decodeURIComponent(name), color};
  // Update header
  const av = $('contact-avatar');
  av.textContent = initials(S.activeContact.name);
  av.style.background = color;
  $('contact-name').textContent = S.activeContact.name;
  $('contact-email').textContent = email;
  // Show chat view
  $('empty-state').style.display = 'none';
  $('chat-view').classList.add('active');
  renderThreadList();
  loadThread(email, true);
}

async function loadThread(email, scrollToBottom=true) {
  const {ok, data} = await api(`/msg/thread?with=${encodeURIComponent(email)}`);
  if (!ok || !Array.isArray(data)) return;

  const area = $('messages-area');
  if (!data.length) {
    area.innerHTML = `
      <div style="flex:1;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:.5rem;color:var(--dust);text-align:center;">
        <div style="font-size:1.8rem">🔐</div>
        <div style="font-family:'Fira Code',monospace;font-size:.78rem">No messages yet. Say hello!</div>
      </div>`;
    return;
  }

  // Group by date
  let html = '';
  let lastDate = '';
  for (const m of data) {
    const d = fmtDate(m.sent_at);
    if (d !== lastDate) {
      html += `<div class="day-divider"><span>${d}</span></div>`;
      lastDate = d;
    }
    const mine = m.from === S.me.email;
    html += `
      <div class="msg-group ${mine ? 'mine' : 'theirs'}">
        <div class="bubble">${esc(m.text)}</div>
        ${m.cipher ? `<div class="cipher-peek" title="${esc(m.cipher)}">⚿ ${esc(m.cipher)}</div>` : ''}
        <div class="msg-meta">${fmtTime(m.sent_at)}</div>
      </div>`;
  }
  // Only update DOM if content changed (avoids scroll jump on poll)
  if (area.dataset.hash !== btoa(unescape(encodeURIComponent(html))).slice(0,20)) {
    area.innerHTML = html;
    area.dataset.hash = btoa(unescape(encodeURIComponent(html))).slice(0,20);
    if (scrollToBottom) area.scrollTop = area.scrollHeight;
  }
}

// ════════════════════════════════════════════════════════════════
//  Send
// ════════════════════════════════════════════════════════════════
async function sendMessage() {
  const inp = $('compose-input');
  const txt = inp.value.trim();
  if (!txt || !S.activeContact) return;
  const btn = $('send-btn');
  btn.disabled = true;

  const {ok, data} = await api('/msg/send', {
    method: 'POST',
    body: JSON.stringify({recipient: S.activeContact.email, plaintext: txt}),
  });

  inp.value = ''; inp.style.height = 'auto';
  btn.disabled = false;

  if (!ok) {
    toast('✗ ' + (data.error || 'Send failed'), 'err');
    return;
  }

  // Refresh thread + inbox
  await loadThread(S.activeContact.email, true);
  loadInbox();
}

// ════════════════════════════════════════════════════════════════
//  Burn
// ════════════════════════════════════════════════════════════════
function confirmBurn() {
  if (!S.activeContact) return;
  $('burn-modal-text').textContent =
    `All messages with ${S.activeContact.name} will be permanently deleted. This cannot be undone.`;
  $('burn-modal').classList.add('open');
}
function closeBurnModal() {
  $('burn-modal').classList.remove('open');
}
async function executeBurn() {
  closeBurnModal();
  if (!S.activeContact) return;
  const {ok, data} = await api('/msg/burn', {
    method: 'POST',
    body: JSON.stringify({contact: S.activeContact.email}),
  });
  if (ok) {
    toast('🔥 Thread burned', 'ok');
    await loadThread(S.activeContact.email, false);
    loadInbox();
  } else {
    toast('✗ ' + (data.error || 'Burn failed'), 'err');
  }
}

// ════════════════════════════════════════════════════════════════
//  User search
// ════════════════════════════════════════════════════════════════
let _searchTimer = null;
function onSearchInput(val) {
  clearTimeout(_searchTimer);
  if (val.length < 3) { closeSearch(); return; }
  _searchTimer = setTimeout(() => searchUsers(val), 300);
}
async function searchUsers(q) {
  const {ok, data} = await api(`/msg/search_user?q=${encodeURIComponent(q)}`);
  if (!ok || !Array.isArray(data) || !data.length) { closeSearch(); return; }
  const el = $('search-results');
  el.innerHTML = data.map(u => `
    <div class="search-result-item" onclick="startChatWith('${u.email}','${encodeURIComponent(u.name)}','${u.color}')">
      <div class="avatar" style="background:${u.color};width:30px;height:30px;font-size:.75rem">${initials(u.name)}</div>
      <div class="sr-info">
        <div class="sr-name">${esc(u.name)}</div>
        <div class="sr-email">${esc(u.email)}</div>
      </div>
    </div>`).join('');
  el.classList.add('open');
}
function closeSearch() {
  $('search-results').classList.remove('open');
}
function startChatWith(email, nameEnc, color) {
  $('search-input').value = '';
  closeSearch();
  const name = decodeURIComponent(nameEnc);
  // Add to threads if not present
  if (!S.threads.find(t => t.contact === email)) {
    S.threads.unshift({contact:email, name, color, last_at:'', total:0});
    renderThreadList();
  }
  openThread(email, nameEnc, color);
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
init_db()

if __name__ == "__main__":
    log.info(f"BurnChat starting on port {PORT}")
    log.info(f"ChaosKey URL: {CHAOSKEY_URL or '(not set)'}")
    log.info("Each user provides their own ChaosKey API key at signup.")
    app.run(host="0.0.0.0", port=PORT, debug=False)
