"""
CryptoAPI — Key Issuance & Encryption-as-a-Service
+ BurnChat Message Relay
====================================================
- PostgreSQL support via DATABASE_URL (Neon serverless compatible)
- SQLite fallback for local development
- Admin tier with unlimited quota + special admin endpoints
- Admin account seeded automatically from env vars on first boot
- Daily quota removed for admin tier
- Passwords: bcrypt with fallback to sha256
- BurnChat: /api/send, /api/get_messages, /api/delete_messages, /api/inbox
- BurnChat UI served at /chat
"""

import os, secrets, hashlib, hmac, time, logging, json
from datetime import datetime, timezone
from functools import wraps

import requests
from flask import Flask, request, jsonify, g, abort, render_template_string
from flask_cors import CORS

# ── bcrypt ────────────────────────────────────────────────────────────────────
try:
    import bcrypt as _bcrypt
    def hash_password(pw: str) -> str:
        return _bcrypt.hashpw(pw.encode(), _bcrypt.gensalt(12)).decode()
    def check_password(pw: str, hashed: str) -> bool:
        return _bcrypt.checkpw(pw.encode(), hashed.encode())
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

# ── Config ────────────────────────────────────────────────────────────────────
RELAY_TOKEN       = os.getenv("RELAY_TOKEN", "")
ADMIN_SECRET      = os.getenv("ADMIN_SECRET", "")
DATABASE_URL      = os.getenv("DATABASE_URL", "")
DB_PATH           = os.getenv("DB_PATH", "chaoskey.db")
DYNAMIC_RELAY_URL = os.getenv("RELAY_URL", "")

ADMIN_EMAIL       = os.getenv("ADMIN_EMAIL", "admin@admin.com")
ADMIN_PASSWORD    = os.getenv("ADMIN_PASSWORD", "")

FREE_QUOTA_DAY  = 100
PRO_QUOTA_DAY   = 10_000
ADMIN_QUOTA_DAY = 999_999_999
KEY_PREFIX      = "ck_live_"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("CryptoAPI")

if not RELAY_TOKEN:
    log.warning("RELAY_TOKEN env var not set — bridge authentication disabled.")
if not ADMIN_SECRET:
    log.warning("ADMIN_SECRET env var not set — admin endpoints are unprotected!")

app = Flask("CryptoAPI")
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=False)

# ── Database abstraction (PostgreSQL or SQLite) ───────────────────────────────
USE_POSTGRES = bool(DATABASE_URL)

if USE_POSTGRES:
    import psycopg2
    import psycopg2.extras

    def _make_conn():
        url = DATABASE_URL
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql://", 1)
        return psycopg2.connect(url)

    def get_db():
        if "db" not in g:
            g.db = _make_conn()
            g.db.autocommit = False
        return g.db

    @app.teardown_appcontext
    def close_db(exc):
        db = g.pop("db", None)
        if db:
            if exc:
                db.rollback()
            else:
                db.commit()
            db.close()

    def db_execute(sql, params=()):
        sql = sql.replace("?", "%s")
        cur = get_db().cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql, params)
        return cur

    def db_lastrowid(cur):
        cur.execute("SELECT lastval()")
        return cur.fetchone()["lastval"]

    def db_commit():
        get_db().commit()

    AUTOINCREMENT = "SERIAL PRIMARY KEY"

else:
    import sqlite3

    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA journal_mode=WAL")
        return g.db

    @app.teardown_appcontext
    def close_db(exc):
        db = g.pop("db", None)
        if db:
            db.close()

    def db_execute(sql, params=()):
        return get_db().execute(sql, params)

    def db_lastrowid(cur):
        return cur.lastrowid

    def db_commit():
        get_db().commit()

    AUTOINCREMENT = "INTEGER PRIMARY KEY AUTOINCREMENT"


# ── Schema ────────────────────────────────────────────────────────────────────
def get_schema():
    ai = AUTOINCREMENT
    return f"""
CREATE TABLE IF NOT EXISTS customers (
    id            {ai},
    email         TEXT UNIQUE NOT NULL,
    name          TEXT NOT NULL,
    tier          TEXT NOT NULL DEFAULT 'free',
    created_at    TEXT NOT NULL,
    active        INTEGER NOT NULL DEFAULT 1,
    password_hash TEXT
);
CREATE TABLE IF NOT EXISTS api_keys (
    id          {ai},
    customer_id INTEGER NOT NULL REFERENCES customers(id),
    key_hash    TEXT UNIQUE NOT NULL,
    key_prefix  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    revoked_at  TEXT,
    label       TEXT DEFAULT 'default'
);
CREATE TABLE IF NOT EXISTS usage_log (
    id          {ai},
    key_id      INTEGER NOT NULL REFERENCES api_keys(id),
    endpoint    TEXT NOT NULL,
    ts          TEXT NOT NULL,
    status      INTEGER NOT NULL,
    latency_ms  INTEGER
);
CREATE TABLE IF NOT EXISTS daily_counts (
    key_id  INTEGER NOT NULL REFERENCES api_keys(id),
    day     TEXT NOT NULL,
    count   INTEGER NOT NULL DEFAULT 0,
    {"UNIQUE(key_id, day)" if USE_POSTGRES else "PRIMARY KEY (key_id, day)"}
);
CREATE TABLE IF NOT EXISTS chat_messages (
    id          {ai},
    sender      TEXT NOT NULL,
    recipient   TEXT NOT NULL,
    payload     TEXT NOT NULL,
    timestamp   TEXT NOT NULL
);
"""


def init_db():
    with app.app_context():
        if USE_POSTGRES:
            url = DATABASE_URL
            if url.startswith("postgres://"):
                url = url.replace("postgres://", "postgresql://", 1)
            conn = psycopg2.connect(url)
            conn.autocommit = True
            cur = conn.cursor()
            for stmt in get_schema().split(";"):
                stmt = stmt.strip()
                if stmt:
                    try:
                        cur.execute(stmt)
                    except Exception as e:
                        log.warning(f"Schema stmt skipped: {e}")
            try:
                cur.execute("ALTER TABLE customers ADD COLUMN IF NOT EXISTS password_hash TEXT")
            except Exception:
                pass
            conn.close()
        else:
            db = sqlite3.connect(DB_PATH)
            db.executescript(get_schema())
            try:
                db.execute("ALTER TABLE customers ADD COLUMN password_hash TEXT")
                db.commit()
            except Exception:
                pass
            db.commit()
            db.close()

        _seed_admin()


def _seed_admin():
    if not ADMIN_PASSWORD:
        log.warning("[Init] ADMIN_PASSWORD not set — admin account NOT created.")
        return

    try:
        existing = db_execute(
            "SELECT id FROM customers WHERE email = ?", (ADMIN_EMAIL,)
        ).fetchone()

        if existing:
            db_execute(
                "UPDATE customers SET tier = 'admin', password_hash = ? WHERE email = ?",
                (hash_password(ADMIN_PASSWORD), ADMIN_EMAIL)
            )
            db_commit()
            log.info(f"[Init] Admin account refreshed: {ADMIN_EMAIL}")
            return

        pw_hash = hash_password(ADMIN_PASSWORD)
        db_execute(
            "INSERT INTO customers (email, name, tier, created_at, password_hash) VALUES (?, ?, 'admin', ?, ?)",
            (ADMIN_EMAIL, "Admin", now_iso(), pw_hash)
        )
        db_commit()

        cust = db_execute("SELECT id FROM customers WHERE email = ?", (ADMIN_EMAIL,)).fetchone()
        cust_id = cust["id"]

        raw_key, key_hash, prefix = mint_key()
        db_execute(
            "INSERT INTO api_keys (customer_id, key_hash, key_prefix, created_at, label) VALUES (?, ?, ?, ?, 'admin')",
            (cust_id, key_hash, prefix, now_iso())
        )
        db_commit()
        log.info(f"[Init] Admin account created: {ADMIN_EMAIL}")
        log.info(f"[Init] Admin API key: {raw_key}")

    except Exception as e:
        log.error(f"[Init] Failed to seed admin: {e}")


# ── Helpers ───────────────────────────────────────────────────────────────────
def mint_key():
    raw = KEY_PREFIX + secrets.token_urlsafe(32)
    return raw, hashlib.sha256(raw.encode()).hexdigest(), raw[:16] + "…"

def today():   return datetime.now(timezone.utc).strftime("%Y-%m-%d")
def now_iso(): return datetime.now(timezone.utc).isoformat()

def quota_for_tier(tier: str) -> int:
    return {"free": FREE_QUOTA_DAY, "pro": PRO_QUOTA_DAY, "admin": ADMIN_QUOTA_DAY}.get(tier, FREE_QUOTA_DAY)


# ── Auth middleware ───────────────────────────────────────────────────────────
def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing Authorization header"}), 401

        key_hash = hashlib.sha256(auth[7:].encode()).hexdigest()
        row = db_execute(
            "SELECT k.id, k.customer_id, c.tier, c.active, k.revoked_at "
            "FROM api_keys k JOIN customers c ON c.id = k.customer_id "
            "WHERE k.key_hash = ?", (key_hash,)
        ).fetchone()

        if not row:               return jsonify({"error": "Invalid API key"}), 401
        if row["revoked_at"]:     return jsonify({"error": "API key revoked"}), 401
        if not row["active"]:     return jsonify({"error": "Account suspended"}), 403

        if row["tier"] != "admin":
            quota = quota_for_tier(row["tier"])
            cnt = db_execute(
                "SELECT count FROM daily_counts WHERE key_id = ? AND day = ?",
                (row["id"], today())
            ).fetchone()
            if (cnt["count"] if cnt else 0) >= quota:
                return jsonify({"error": "Daily quota exceeded"}), 429

        g.key_id      = row["id"]
        g.customer_id = row["customer_id"]
        g.tier        = row["tier"]
        g.t0          = time.monotonic()
        return f(*args, **kwargs)
    return decorated


def log_usage(endpoint: str, status: int):
    if not hasattr(g, "key_id"):
        return
    try:
        db_execute(
            "INSERT INTO usage_log (key_id, endpoint, ts, status, latency_ms) VALUES (?, ?, ?, ?, ?)",
            (g.key_id, endpoint, now_iso(), status, int((time.monotonic() - g.t0) * 1000))
        )
        upsert_sql = (
            "INSERT INTO daily_counts (key_id, day, count) VALUES (%s, %s, 1) "
            "ON CONFLICT (key_id, day) DO UPDATE SET count = daily_counts.count + 1"
            if USE_POSTGRES else
            "INSERT INTO daily_counts (key_id, day, count) VALUES (?, ?, 1) "
            "ON CONFLICT(key_id, day) DO UPDATE SET count = count + 1"
        )
        db_execute(upsert_sql, (g.key_id, today()))
        db_commit()
    except Exception as e:
        log.warning(f"log_usage failed: {e}")


# ── Relay helper ──────────────────────────────────────────────────────────────
def relay_request(path, method="GET", body=None):
    if not DYNAMIC_RELAY_URL:
        return None, {"error": "Local engine offline — start the launcher on your machine"}, 503
    try:
        resp = requests.request(
            method, DYNAMIC_RELAY_URL.rstrip("/") + path,
            headers={
                "X-Relay-Token": RELAY_TOKEN,
                "Content-Type": "application/json",
            },
            json=body, timeout=20
        )
        try:
            data = resp.json()
        except Exception:
            data = {
                "error": (
                    f"Bridge returned a non-JSON response (HTTP {resp.status_code}). "
                    "The local encryption bridge may be down — check the launcher."
                )
            }

        if resp.status_code == 403:
            data = {
                "error": (
                    "Bridge rejected the request (token mismatch). "
                    "RELAY_TOKEN on Render must exactly match BRIDGE_SECRET in your local .env."
                )
            }

        return resp, data, resp.status_code
    except requests.exceptions.ConnectionError:
        return None, {"error": "Cannot reach the local bridge — is the launcher running and tunnel active?"}, 503
    except requests.exceptions.Timeout:
        return None, {"error": "Bridge timed out — the local machine may be overloaded"}, 504
    except Exception as e:
        return None, {"error": str(e)}, 500


# ── Error handlers ────────────────────────────────────────────────────────────
@app.errorhandler(400)
def err400(e): return jsonify({"error": "Bad request", "detail": str(e)}), 400
@app.errorhandler(401)
def err401(e): return jsonify({"error": "Unauthorized"}), 401
@app.errorhandler(403)
def err403(e): return jsonify({"error": "Forbidden"}), 403
@app.errorhandler(404)
def err404(e): return jsonify({"error": "Not found"}), 404
@app.errorhandler(429)
def err429(e): return jsonify({"error": "Too many requests"}), 429
@app.errorhandler(500)
def err500(e): return jsonify({"error": "Internal server error", "detail": str(e)}), 500


# ════════════════════════════════════════════════════════════════
#  ADMIN ENDPOINTS
# ════════════════════════════════════════════════════════════════

def admin_auth():
    return hmac.compare_digest(
        request.headers.get("X-Admin-Secret", ""), ADMIN_SECRET
    )


@app.route("/admin/set_relay", methods=["POST"])
def set_relay():
    if not admin_auth(): abort(403)
    global DYNAMIC_RELAY_URL
    new_url = (request.get_json(force=True) or {}).get("url")
    if not new_url: return jsonify({"error": "Missing URL"}), 400
    DYNAMIC_RELAY_URL = new_url
    log.info(f"Relay updated to: {DYNAMIC_RELAY_URL}")
    return jsonify({"message": "Relay updated", "url": DYNAMIC_RELAY_URL})


@app.route("/admin/register", methods=["POST"])
def admin_register():
    if not admin_auth(): abort(403)
    body  = request.get_json(force=True) or {}
    email = body.get("email", "").strip().lower()
    name  = body.get("name", "").strip()
    tier  = body.get("tier", "free")
    pw    = body.get("password", "")
    if not email or not name: return jsonify({"error": "email and name required"}), 400
    if tier not in ("free", "pro", "admin"): return jsonify({"error": "tier must be free, pro, or admin"}), 400
    try:
        pw_hash = hash_password(pw) if pw else None
        db_execute(
            "INSERT INTO customers (email, name, tier, created_at, password_hash) VALUES (?, ?, ?, ?, ?)",
            (email, name, tier, now_iso(), pw_hash)
        )
        db_commit()
        cust = db_execute("SELECT id FROM customers WHERE email = ?", (email,)).fetchone()
        raw_key, key_hash, prefix = mint_key()
        db_execute(
            "INSERT INTO api_keys (customer_id, key_hash, key_prefix, created_at) VALUES (?, ?, ?, ?)",
            (cust["id"], key_hash, prefix, now_iso())
        )
        db_commit()
        return jsonify({"message": "Customer registered", "api_key": raw_key,
                        "email": email, "name": name, "tier": tier}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 409


@app.route("/admin/customers", methods=["GET"])
def admin_customers():
    if not admin_auth(): abort(403)
    rows = db_execute(
        "SELECT c.id, c.email, c.name, c.tier, c.active, c.created_at, "
        "COUNT(k.id) as key_count FROM customers c "
        "LEFT JOIN api_keys k ON k.customer_id = c.id "
        "GROUP BY c.id ORDER BY c.created_at DESC"
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/admin/customers/<int:cid>/tier", methods=["PATCH"])
def admin_set_tier(cid):
    if not admin_auth(): abort(403)
    tier = (request.get_json(force=True) or {}).get("tier")
    if tier not in ("free", "pro", "admin"):
        return jsonify({"error": "tier must be free, pro, or admin"}), 400
    db_execute("UPDATE customers SET tier = ? WHERE id = ?", (tier, cid))
    db_commit()
    return jsonify({"message": f"Customer {cid} set to tier={tier}"})


@app.route("/admin/customers/<int:cid>/suspend", methods=["POST"])
def admin_suspend(cid):
    if not admin_auth(): abort(403)
    db_execute("UPDATE customers SET active = 0 WHERE id = ?", (cid,))
    db_commit()
    return jsonify({"message": f"Customer {cid} suspended"})


@app.route("/admin/customers/<int:cid>/unsuspend", methods=["POST"])
def admin_unsuspend(cid):
    if not admin_auth(): abort(403)
    db_execute("UPDATE customers SET active = 1 WHERE id = ?", (cid,))
    db_commit()
    return jsonify({"message": f"Customer {cid} reinstated"})


@app.route("/admin/customers/<int:cid>/keys", methods=["GET"])
def admin_list_keys(cid):
    if not admin_auth(): abort(403)
    rows = db_execute(
        "SELECT id, key_prefix, created_at, revoked_at, label FROM api_keys WHERE customer_id = ? ORDER BY id DESC",
        (cid,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/admin/stats", methods=["GET"])
def admin_stats():
    if not admin_auth(): abort(403)
    total_req  = db_execute("SELECT COUNT(*) as c FROM usage_log").fetchone()["c"]
    today_req  = db_execute("SELECT SUM(count) as c FROM daily_counts WHERE day = ?", (today(),)).fetchone()["c"]
    total_cust = db_execute("SELECT COUNT(*) as c FROM customers WHERE active = 1").fetchone()["c"]
    tier_breakdown = db_execute(
        "SELECT tier, COUNT(*) as c FROM customers WHERE active = 1 GROUP BY tier"
    ).fetchall()
    top_users = db_execute(
        "SELECT c.email, c.tier, SUM(d.count) as total "
        "FROM daily_counts d JOIN api_keys k ON k.id = d.key_id "
        "JOIN customers c ON c.id = k.customer_id "
        "GROUP BY c.email, c.tier ORDER BY total DESC LIMIT 10"
    ).fetchall()
    total_msgs = db_execute("SELECT COUNT(*) as c FROM chat_messages").fetchone()["c"]
    return jsonify({
        "total_customers":     total_cust,
        "total_requests":      total_req,
        "today_requests":      today_req or 0,
        "total_chat_messages": total_msgs,
        "relay_active":        bool(DYNAMIC_RELAY_URL),
        "relay_url":           DYNAMIC_RELAY_URL or None,
        "tier_breakdown":      [dict(r) for r in tier_breakdown],
        "top_users":           [dict(r) for r in top_users],
    })


@app.route("/admin/usage_log", methods=["GET"])
def admin_usage_log():
    if not admin_auth(): abort(403)
    rows = db_execute(
        "SELECT u.id, c.email, u.endpoint, u.ts, u.status, u.latency_ms "
        "FROM usage_log u JOIN api_keys k ON k.id = u.key_id "
        "JOIN customers c ON c.id = k.customer_id "
        "ORDER BY u.id DESC LIMIT 200"
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/admin/chat_messages", methods=["GET"])
def admin_chat_messages():
    """Admin: view recent chat metadata (payloads are encrypted — no plaintext visible)."""
    if not admin_auth(): abort(403)
    rows = db_execute(
        "SELECT id, sender, recipient, timestamp FROM chat_messages ORDER BY id DESC LIMIT 200"
    ).fetchall()
    return jsonify([dict(r) for r in rows])


# ════════════════════════════════════════════════════════════════
#  PUBLIC AUTH ENDPOINTS
# ════════════════════════════════════════════════════════════════

@app.route("/v1/register", methods=["POST"])
def public_register():
    body     = request.get_json(force=True) or {}
    email    = body.get("email", "").strip().lower()
    password = body.get("password", "").strip()
    name     = body.get("name", "").strip() or email.split("@")[0]

    if not email or "@" not in email:
        return jsonify({"error": "Valid email required"}), 400
    if not password or len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    try:
        pw_hash = hash_password(password)
        db_execute(
            "INSERT INTO customers (email, name, tier, created_at, password_hash) VALUES (?, ?, 'free', ?, ?)",
            (email, name, now_iso(), pw_hash)
        )
        db_commit()
        cust = db_execute("SELECT id FROM customers WHERE email = ?", (email,)).fetchone()
        raw_key, key_hash, prefix = mint_key()
        db_execute(
            "INSERT INTO api_keys (customer_id, key_hash, key_prefix, created_at, label) VALUES (?, ?, ?, ?, 'primary')",
            (cust["id"], key_hash, prefix, now_iso())
        )
        db_commit()
        return jsonify({
            "api_key": raw_key,
            "tier":    "free",
            "quota":   FREE_QUOTA_DAY,
            "note":    "Save this key — it is shown only once.",
        }), 201
    except Exception as e:
        if "unique" in str(e).lower() or "duplicate" in str(e).lower():
            return jsonify({"error": "Email already registered. Please log in instead."}), 409
        return jsonify({"error": str(e)}), 500


@app.route("/v1/login", methods=["POST"])
def public_login():
    body     = request.get_json(force=True) or {}
    email    = body.get("email", "").strip().lower()
    password = body.get("password", "").strip()

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    cust = db_execute(
        "SELECT id, name, tier, active, password_hash FROM customers WHERE email = ?", (email,)
    ).fetchone()

    if not cust:                     return jsonify({"error": "Invalid email or password"}), 401
    if not cust["active"]:           return jsonify({"error": "Account suspended"}), 403
    if not cust["password_hash"]:    return jsonify({"error": "No password set. Contact support."}), 401
    if not check_password(password, cust["password_hash"]):
        return jsonify({"error": "Invalid email or password"}), 401

    key_row = db_execute(
        "SELECT key_hash, key_prefix, created_at FROM api_keys "
        "WHERE customer_id = ? AND revoked_at IS NULL ORDER BY id DESC LIMIT 1",
        (cust["id"],)
    ).fetchone()

    if not key_row:
        return jsonify({"error": "No active key found. Use /v1/rotate_key."}), 404

    quota = quota_for_tier(cust["tier"])
    return jsonify({
        "message":    "Login successful",
        "name":       cust["name"],
        "tier":       cust["tier"],
        "quota":      quota,
        "key_prefix": key_row["key_prefix"],
        "key_created": key_row["created_at"],
        "note": "Raw key shown only once at registration. Use /v1/rotate_key if lost.",
    }), 200


@app.route("/v1/rotate_key", methods=["POST"])
def rotate_key():
    body     = request.get_json(force=True) or {}
    email    = body.get("email", "").strip().lower()
    password = body.get("password", "").strip()

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    cust = db_execute(
        "SELECT id, active, password_hash, tier FROM customers WHERE email = ?", (email,)
    ).fetchone()

    if not cust or not cust["password_hash"] or not check_password(password, cust["password_hash"]):
        return jsonify({"error": "Invalid email or password"}), 401
    if not cust["active"]:
        return jsonify({"error": "Account suspended"}), 403

    db_execute(
        "UPDATE api_keys SET revoked_at = ? WHERE customer_id = ? AND revoked_at IS NULL",
        (now_iso(), cust["id"])
    )
    raw_key, key_hash, prefix = mint_key()
    db_execute(
        "INSERT INTO api_keys (customer_id, key_hash, key_prefix, created_at, label) VALUES (?, ?, ?, ?, 'primary')",
        (cust["id"], key_hash, prefix, now_iso())
    )
    db_commit()
    return jsonify({
        "api_key": raw_key,
        "tier":    cust["tier"],
        "note":    "Old key revoked. Save this new key — not shown again.",
    }), 201


# ════════════════════════════════════════════════════════════════
#  AUTHENTICATED API ENDPOINTS
# ════════════════════════════════════════════════════════════════

@app.route("/v1/keys", methods=["POST"])
def issue_key():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Missing Authorization header"}), 401
    key_hash = hashlib.sha256(auth[7:].encode()).hexdigest()
    row = db_execute(
        "SELECT k.customer_id, k.revoked_at, c.active FROM api_keys k "
        "JOIN customers c ON c.id = k.customer_id WHERE k.key_hash = ?", (key_hash,)
    ).fetchone()
    if not row or row["revoked_at"] or not row["active"]:
        return jsonify({"error": "Invalid or revoked API key"}), 401
    label = (request.get_json(force=True) or {}).get("label", "secondary")
    raw_key, new_hash, prefix = mint_key()
    db_execute(
        "INSERT INTO api_keys (customer_id, key_hash, key_prefix, created_at, label) VALUES (?, ?, ?, ?, ?)",
        (row["customer_id"], new_hash, prefix, now_iso(), label)
    )
    db_commit()
    return jsonify({"api_key": raw_key, "label": label,
                    "note": "Store this key safely — not shown again."}), 201


@app.route("/v1/usage", methods=["GET"])
@require_api_key
def usage():
    today_count = db_execute(
        "SELECT count FROM daily_counts WHERE key_id = ? AND day = ?", (g.key_id, today())
    ).fetchone()
    quota = quota_for_tier(g.tier)
    recent = db_execute(
        "SELECT endpoint, ts, status, latency_ms FROM usage_log "
        "WHERE key_id = ? ORDER BY id DESC LIMIT 20", (g.key_id,)
    ).fetchall()
    used = today_count["count"] if today_count else 0
    return jsonify({
        "tier":            g.tier,
        "quota_today":     quota if g.tier != "admin" else "unlimited",
        "used_today":      used,
        "remaining_today": max(0, quota - used) if g.tier != "admin" else "unlimited",
        "recent_calls":    [dict(r) for r in recent],
    })


@app.route("/v1/encrypt", methods=["POST"])
@require_api_key
def encrypt():
    body = request.get_json(force=True) or {}
    if "plaintext" not in body:
        return jsonify({"error": "Missing 'plaintext' field"}), 400
    _, data, status = relay_request("/relay/encrypt", "POST", {"plaintext": body.get("plaintext")})
    log_usage("/v1/encrypt", status)
    return jsonify(data), status


@app.route("/v1/decrypt", methods=["POST"])
@require_api_key
def decrypt():
    body = request.get_json(force=True) or {}
    if not {"ciphertext", "nonce", "encryption_key"}.issubset(body):
        return jsonify({"error": "Missing ciphertext, nonce, or encryption_key"}), 400
    _, data, status = relay_request("/relay/decrypt", "POST", {
        "ciphertext":     body.get("ciphertext"),
        "nonce":          body.get("nonce"),
        "encryption_key": body.get("encryption_key"),
    })
    log_usage("/v1/decrypt", status)
    return jsonify(data), status


@app.route("/v1/export_key", methods=["GET"])
@require_api_key
def export_key():
    _, data, status = relay_request("/relay/export_key", "GET")
    log_usage("/v1/export_key", status)
    return jsonify(data), status


@app.route("/v1/status", methods=["GET"])
@require_api_key
def api_status():
    _, data, status = relay_request("/relay/status")
    return jsonify(data), status


# ── Public stats ──────────────────────────────────────────────────────────────
@app.route("/public/stats", methods=["GET"])
def public_stats():
    total = db_execute("SELECT COUNT(*) as c FROM customers WHERE active = 1").fetchone()["c"]
    today_req = db_execute(
        "SELECT SUM(count) as c FROM daily_counts WHERE day = ?", (today(),)
    ).fetchone()["c"]
    return jsonify({"total_customers": total, "today_requests": today_req or 0})


@app.route("/health")
def health():
    return jsonify({
        "status":        "ok",
        "tunnel_active": bool(DYNAMIC_RELAY_URL),
        "relay_url":     DYNAMIC_RELAY_URL or None,
        "db_backend":    "postgresql" if USE_POSTGRES else "sqlite",
    })


# ════════════════════════════════════════════════════════════════
#  BURNCHAT MESSAGE RELAY
# ════════════════════════════════════════════════════════════════

@app.route("/api/send", methods=["POST"])
def chat_send():
    """
    Store an encrypted message bundle.
    Body: { sender, recipient, payload: { from, plaintext, ciphertext, nonce, encryption_key } }
    The server stores the full payload (including plaintext) — use this route only over HTTPS.
    The ciphertext + nonce + encryption_key fields allow the recipient to independently decrypt.
    """
    body      = request.get_json(force=True) or {}
    sender    = body.get("sender", "").strip().lower()
    recipient = body.get("recipient", "").strip().lower()
    payload   = body.get("payload")

    if not sender or not recipient or payload is None:
        return jsonify({"error": "sender, recipient, and payload are required"}), 400
    if "@" not in sender:
        return jsonify({"error": "Invalid sender email"}), 400
    if "@" not in recipient:
        return jsonify({"error": "Invalid recipient email"}), 400

    db_execute(
        "INSERT INTO chat_messages (sender, recipient, payload, timestamp) VALUES (?, ?, ?, ?)",
        (sender, recipient, json.dumps(payload), now_iso())
    )
    db_commit()
    return jsonify({"ok": True}), 201


@app.route("/api/get_messages", methods=["GET"])
def chat_get_messages():
    """
    Fetch all messages between two users (both directions), ordered oldest first.
    Query params: user, contact
    Returns: [ { sender, recipient, payload, timestamp }, ... ]
    """
    user    = request.args.get("user", "").strip().lower()
    contact = request.args.get("contact", "").strip().lower()

    if not user or not contact:
        return jsonify({"error": "user and contact query params are required"}), 400

    rows = db_execute(
        "SELECT sender, recipient, payload, timestamp FROM chat_messages "
        "WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?) "
        "ORDER BY id ASC",
        (user, contact, contact, user)
    ).fetchall()

    return jsonify([
        {
            "sender":    r["sender"],
            "recipient": r["recipient"],
            "payload":   r["payload"],   # JSON string — client must parse
            "timestamp": r["timestamp"],
        }
        for r in rows
    ])


@app.route("/api/delete_messages", methods=["POST"])
def chat_delete_messages():
    """
    Delete all messages between two users (burn the thread).
    Body: { user, contact }
    """
    body    = request.get_json(force=True) or {}
    user    = body.get("user", "").strip().lower()
    contact = body.get("contact", "").strip().lower()

    if not user or not contact:
        return jsonify({"error": "user and contact are required"}), 400

    db_execute(
        "DELETE FROM chat_messages WHERE "
        "(sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?)",
        (user, contact, contact, user)
    )
    db_commit()
    return jsonify({"ok": True, "message": "Conversation deleted"})


@app.route("/api/inbox", methods=["GET"])
def chat_inbox():
    """
    Get a summary of all conversations for a user.
    Query param: user
    Returns: [ { contact, last_timestamp, message_count }, ... ]
    """
    user = request.args.get("user", "").strip().lower()
    if not user:
        return jsonify({"error": "user query param required"}), 400

    rows = db_execute(
        "SELECT "
        "  CASE WHEN sender = ? THEN recipient ELSE sender END as contact, "
        "  MAX(timestamp) as last_timestamp, "
        "  COUNT(*) as message_count "
        "FROM chat_messages "
        "WHERE sender = ? OR recipient = ? "
        "GROUP BY contact "
        "ORDER BY last_timestamp DESC",
        (user, user, user)
    ).fetchall()

    return jsonify([dict(r) for r in rows])


# ════════════════════════════════════════════════════════════════
#  BURNCHAT FRONTEND  (served at /chat)
# ════════════════════════════════════════════════════════════════

BURNCHAT_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BurnChat — Encrypted Messaging</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #0f172a; --bg2: #1e293b; --bg3: #0d1829;
            --accent: #38bdf8; --accent2: #0ea5e9;
            --text: #f1f5f9; --text2: #94a3b8;
            --border: #2d3f55; --mine: #0284c7; --theirs: #1e3a5f;
            --radius: 12px; --danger: #ef4444;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Inter', sans-serif; background: var(--bg); color: var(--text); height: 100vh; display: flex; flex-direction: column; }

        /* Auth */
        #auth-screen { flex: 1; display: flex; align-items: center; justify-content: center; }
        .auth-card { width: 100%; max-width: 400px; background: var(--bg2); padding: 2.5rem; border-radius: var(--radius); border: 1px solid var(--border); box-shadow: 0 25px 50px rgba(0,0,0,0.5); }
        .auth-logo { text-align: center; margin-bottom: 2rem; }
        .auth-logo h1 { font-size: 1.6rem; font-weight: 600; }
        .auth-logo p { color: var(--text2); font-size: 0.85rem; margin-top: 0.3rem; }
        .auth-tabs { display: flex; margin-bottom: 1.5rem; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
        .auth-tab { flex: 1; padding: 0.6rem; background: none; border: none; color: var(--text2); font-size: 0.8rem; font-weight: 600; cursor: pointer; transition: all 0.2s; font-family: 'Inter', sans-serif; }
        .auth-tab.active { background: var(--accent); color: #fff; }
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text2); margin-bottom: 0.4rem; }
        .form-group input { width: 100%; padding: 0.7rem 0.9rem; background: var(--bg3); border: 1px solid var(--border); border-radius: 8px; color: var(--text); font-size: 0.9rem; outline: none; font-family: 'Inter', sans-serif; transition: border-color 0.2s; }
        .form-group input:focus { border-color: var(--accent); }
        .btn { width: 100%; padding: 0.75rem; background: var(--accent); color: #fff; border: none; border-radius: 8px; font-weight: 600; font-size: 0.9rem; cursor: pointer; font-family: 'Inter', sans-serif; transition: background 0.2s; }
        .btn:hover { background: var(--accent2); }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .auth-err { color: var(--danger); font-size: 0.8rem; margin-top: 0.75rem; min-height: 1.2rem; text-align: center; }

        /* Chat Layout */
        #chat-screen { flex: 1; display: none; overflow: hidden; }
        .chat-layout { display: flex; height: 100vh; }

        /* Sidebar */
        .sidebar { width: 280px; background: var(--bg2); border-right: 1px solid var(--border); display: flex; flex-direction: column; flex-shrink: 0; }
        .sidebar-header { padding: 1rem 1.2rem; border-bottom: 1px solid var(--border); }
        .user-info { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.75rem; }
        .user-info .uname { font-weight: 600; font-size: 0.9rem; }
        .user-info .utier { font-size: 0.65rem; color: var(--accent); background: rgba(56,189,248,0.1); border: 1px solid rgba(56,189,248,0.2); padding: 0.15rem 0.5rem; border-radius: 20px; }
        .logout-link { font-size: 0.72rem; color: var(--danger); cursor: pointer; background: none; border: none; font-family: 'Inter', sans-serif; }
        .add-contact { display: flex; gap: 0.5rem; }
        .add-contact input { flex: 1; padding: 0.5rem 0.7rem; background: var(--bg3); border: 1px solid var(--border); border-radius: 6px; color: var(--text); font-size: 0.8rem; outline: none; font-family: 'Inter', sans-serif; }
        .add-contact input:focus { border-color: var(--accent); }
        .add-contact button { padding: 0.5rem 0.8rem; background: var(--accent); color: #fff; border: none; border-radius: 6px; font-size: 0.85rem; font-weight: 600; cursor: pointer; }
        .contact-list { flex: 1; overflow-y: auto; }
        .contact-item { padding: 0.9rem 1.2rem; cursor: pointer; display: flex; align-items: center; gap: 10px; border-bottom: 1px solid rgba(255,255,255,0.04); transition: background 0.15s; }
        .contact-item:hover { background: rgba(255,255,255,0.04); }
        .contact-item.active { background: rgba(56,189,248,0.08); border-left: 3px solid var(--accent); }
        .c-avatar { width: 36px; height: 36px; border-radius: 50%; background: rgba(56,189,248,0.15); display: flex; align-items: center; justify-content: center; font-weight: 600; font-size: 0.85rem; color: var(--accent); flex-shrink: 0; }
        .c-name { font-size: 0.88rem; font-weight: 500; }
        .c-email { font-size: 0.7rem; color: var(--text2); }
        .c-badge { margin-left: auto; background: var(--accent); color: #fff; border-radius: 20px; font-size: 0.65rem; padding: 0.1rem 0.45rem; font-weight: 600; }

        /* Chat panel */
        .chat-panel { flex: 1; display: flex; flex-direction: column; background: var(--bg); min-width: 0; }
        .chat-top { padding: 0.9rem 1.5rem; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; background: var(--bg2); }
        .ct-name { font-weight: 600; font-size: 0.95rem; }
        .ct-sub { font-size: 0.7rem; color: var(--accent); margin-top: 2px; }
        .burn-btn { padding: 0.4rem 0.9rem; background: rgba(239,68,68,0.1); color: var(--danger); border: 1px solid rgba(239,68,68,0.2); border-radius: 6px; font-size: 0.75rem; cursor: pointer; font-family: 'Inter', sans-serif; transition: all 0.2s; }
        .burn-btn:hover { background: rgba(239,68,68,0.2); }
        .messages { flex: 1; overflow-y: auto; padding: 1.25rem; display: flex; flex-direction: column; gap: 0.75rem; }
        .empty-chat { flex: 1; display: flex; align-items: center; justify-content: center; flex-direction: column; gap: 0.5rem; color: var(--text2); font-size: 0.9rem; }
        .msg-wrap { display: flex; flex-direction: column; max-width: 68%; }
        .msg-wrap.mine { align-self: flex-end; align-items: flex-end; }
        .msg-wrap.theirs { align-self: flex-start; align-items: flex-start; }
        .bubble { padding: 0.7rem 1rem; border-radius: 14px; font-size: 0.9rem; line-height: 1.55; word-break: break-word; }
        .mine .bubble { background: var(--mine); border-bottom-right-radius: 3px; }
        .theirs .bubble { background: var(--theirs); border: 1px solid var(--border); border-bottom-left-radius: 3px; }
        .msg-meta { font-size: 0.68rem; color: var(--text2); margin-top: 3px; }
        .cipher-peek { font-family: 'JetBrains Mono', monospace; font-size: 0.6rem; color: var(--accent); opacity: 0.5; max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; cursor: help; }
        .compose { padding: 1rem 1.5rem; background: var(--bg2); border-top: 1px solid var(--border); display: flex; gap: 0.75rem; align-items: flex-end; }
        .compose textarea { flex: 1; background: var(--bg3); border: 1px solid var(--border); border-radius: 10px; padding: 0.7rem 1rem; color: var(--text); font-size: 0.9rem; font-family: 'Inter', sans-serif; resize: none; outline: none; line-height: 1.5; max-height: 120px; transition: border-color 0.2s; }
        .compose textarea:focus { border-color: var(--accent); }
        .send-btn { padding: 0.7rem 1.4rem; background: var(--accent); color: #fff; border: none; border-radius: 10px; font-size: 0.9rem; font-weight: 600; cursor: pointer; font-family: 'Inter', sans-serif; transition: background 0.2s; height: 42px; white-space: nowrap; }
        .send-btn:hover { background: var(--accent2); }
        .send-btn:disabled { opacity: 0.4; cursor: not-allowed; }
        .no-chat { flex: 1; display: flex; align-items: center; justify-content: center; color: var(--text2); font-size: 0.9rem; text-align: center; padding: 2rem; }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }
    </style>
</head>
<body>

<!-- Auth Screen -->
<div id="auth-screen">
    <div class="auth-card">
        <div class="auth-logo">
            <h1>🔥 BurnChat</h1>
            <p>End-to-end encrypted messaging via ChaosKey</p>
        </div>
        <div class="auth-tabs">
            <button class="auth-tab active" id="tab-login" onclick="switchTab('login')">Sign In</button>
            <button class="auth-tab" id="tab-register" onclick="switchTab('register')">Register</button>
        </div>
        <div class="form-group">
            <label>Email</label>
            <input id="auth-email" type="email" placeholder="you@example.com" autocomplete="email"
                onkeydown="if(event.key==='Enter')document.getElementById('auth-pw').focus()">
        </div>
        <div class="form-group">
            <label>Password</label>
            <input id="auth-pw" type="password" placeholder="••••••••" autocomplete="current-password"
                onkeydown="if(event.key==='Enter')doAuth()">
        </div>
        <div class="form-group" id="name-group" style="display:none">
            <label>Your name (optional)</label>
            <input id="auth-name" type="text" placeholder="Display name">
        </div>
        <button class="btn" id="auth-btn" onclick="doAuth()">Sign In →</button>
        <div class="auth-err" id="auth-err"></div>
    </div>
</div>

<!-- Chat Screen -->
<div id="chat-screen">
    <div class="chat-layout">
        <!-- Sidebar -->
        <div class="sidebar">
            <div class="sidebar-header">
                <div class="user-info">
                    <div>
                        <div class="uname" id="sb-name">User</div>
                        <div class="utier" id="sb-tier">FREE</div>
                    </div>
                    <button class="logout-link" onclick="doLogout()">Sign out</button>
                </div>
                <div class="add-contact">
                    <input id="add-input" type="email" placeholder="Add contact by email…"
                        onkeydown="if(event.key==='Enter')addContact()">
                    <button onclick="addContact()">+</button>
                </div>
            </div>
            <div class="contact-list" id="contact-list">
                <div style="padding:1rem;font-size:0.8rem;color:var(--text2)">
                    Add a contact above to begin.
                </div>
            </div>
        </div>

        <!-- Main chat -->
        <div class="chat-panel">
            <div class="no-chat" id="no-chat">
                Select or add a contact to start an encrypted conversation.
            </div>
            <div id="active-chat" style="display:none;flex-direction:column;height:100%">
                <div class="chat-top">
                    <div>
                        <div class="ct-name" id="ct-name"></div>
                        <div class="ct-sub">🔐 AES-256-GCM · keys rotate every 10s</div>
                    </div>
                    <button class="burn-btn" onclick="burnThread()">🔥 Burn thread</button>
                </div>
                <div class="messages" id="messages-area"></div>
                <div class="compose">
                    <textarea id="compose-input" rows="1"
                        placeholder="Type an encrypted message… (Enter to send)"
                        oninput="this.style.height='auto';this.style.height=Math.min(this.scrollHeight,120)+'px'"
                        onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendMessage();}"></textarea>
                    <button class="send-btn" id="send-btn" onclick="sendMessage()">Send</button>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
// ── State ──────────────────────────────────────────────────────────────────
const S = {
    apiKey: '', myEmail: '', myName: '',
    contacts: [], messages: {}, unread: {},
    active: null, pollTimer: null, authMode: 'login'
};

// ── Tiny helpers ───────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const esc = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const initials = e => (e||'?')[0].toUpperCase();
const shortTs  = iso => iso ? iso.slice(11,16) : new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});

async function api(path, opts = {}) {
    try {
        const r = await fetch(path, { ...opts, headers: {'Content-Type':'application/json', ...(opts.headers||{})} });
        return { ok: r.ok, data: await r.json() };
    } catch(e) { return { ok: false, data: { error: e.message } }; }
}

// ── Auth ───────────────────────────────────────────────────────────────────
function switchTab(mode) {
    S.authMode = mode;
    $('tab-login').classList.toggle('active', mode==='login');
    $('tab-register').classList.toggle('active', mode==='register');
    $('auth-btn').textContent = mode==='login' ? 'Sign In →' : 'Create Account →';
    $('name-group').style.display = mode==='register' ? 'block' : 'none';
    $('auth-err').textContent = '';
}

async function doAuth() {
    const email = $('auth-email').value.trim().toLowerCase();
    const pw    = $('auth-pw').value;
    const name  = $('auth-name').value.trim();
    const err   = $('auth-err');
    const btn   = $('auth-btn');
    if (!email || !pw) { err.textContent = 'Email and password required.'; return; }
    btn.disabled = true;
    err.textContent = S.authMode==='login' ? 'Signing in…' : 'Creating account…';

    if (S.authMode === 'register') {
        const {ok, data} = await api('/v1/register', {method:'POST', body:JSON.stringify({email,password:pw,name})});
        if (!ok) { err.textContent = '✗ '+(data.error||'Registration failed'); btn.disabled=false; return; }
        S.apiKey   = data.api_key;
        S.myEmail  = email;
        S.myName   = name || email.split('@')[0];
        enterChat('free');
    } else {
        const {ok, data} = await api('/v1/login', {method:'POST', body:JSON.stringify({email,password:pw})});
        if (!ok) { err.textContent = '✗ '+(data.error||'Login failed'); btn.disabled=false; return; }
        // Rotate to get a fresh session key
        const rot = await api('/v1/rotate_key', {method:'POST', body:JSON.stringify({email,password:pw})});
        if (rot.ok) S.apiKey = rot.data.api_key;
        S.myEmail = email;
        S.myName  = data.name || email.split('@')[0];
        enterChat(data.tier);
    }
}

function enterChat(tier) {
    $('auth-screen').style.display = 'none';
    $('chat-screen').style.display = 'flex';
    $('sb-name').textContent = S.myName;
    $('sb-tier').textContent = (tier||'free').toUpperCase();
    startPolling();
}

function doLogout() {
    stopPolling();
    Object.assign(S, {apiKey:'',myEmail:'',myName:'',contacts:[],messages:{},unread:{},active:null});
    $('auth-screen').style.display = 'flex';
    $('chat-screen').style.display = 'none';
    $('auth-pw').value = '';
    $('auth-btn').disabled = false;
    $('auth-err').textContent = '';
    renderContacts();
}

// ── Contacts ───────────────────────────────────────────────────────────────
function addContact() {
    const inp   = $('add-input');
    const email = inp.value.trim().toLowerCase();
    if (!email || !email.includes('@') || email===S.myEmail) { inp.value=''; return; }
    if (!S.contacts.includes(email)) {
        S.contacts.push(email);
        S.messages[email] = S.messages[email] || [];
        S.unread[email]   = 0;
    }
    inp.value = '';
    renderContacts();
    openConversation(email);
}

function renderContacts() {
    const el = $('contact-list');
    if (!S.contacts.length) {
        el.innerHTML = '<div style="padding:1rem;font-size:0.8rem;color:var(--text2)">Add a contact above to begin.</div>';
        return;
    }
    el.innerHTML = S.contacts.map(email => {
        const u = S.unread[email]||0;
        return `<div class="contact-item${S.active===email?' active':''}" onclick="openConversation('${email}')">
            <div class="c-avatar">${initials(email)}</div>
            <div><div class="c-name">${email.split('@')[0]}</div><div class="c-email">${email}</div></div>
            ${u>0?`<div class="c-badge">${u}</div>`:''}
        </div>`;
    }).join('');
}

// ── Conversation ───────────────────────────────────────────────────────────
function openConversation(email) {
    S.active = email; S.unread[email]=0;
    $('no-chat').style.display = 'none';
    $('active-chat').style.display = 'flex';
    $('ct-name').textContent = email;
    renderContacts();
    renderMessages();
    loadMessages();
}

function renderMessages() {
    const msgs = S.messages[S.active]||[];
    const area = $('messages-area');
    if (!area) return;
    if (!msgs.length) {
        area.innerHTML = `<div class="empty-chat"><div style="font-size:2rem;margin-bottom:0.5rem">🔐</div><div>No messages yet — say hello!</div><div style="font-size:0.75rem;margin-top:0.25rem;color:var(--text2)">All messages are AES-256-GCM encrypted</div></div>`;
        return;
    }
    area.innerHTML = msgs.map(m => `
        <div class="msg-wrap ${m.from===S.myEmail?'mine':'theirs'}">
            <div class="bubble">${esc(m.text)}</div>
            ${m.cipher?`<div class="cipher-peek" title="Ciphertext: ${m.cipher}">⚿ ${m.cipher.slice(0,30)}…</div>`:''}
            <div class="msg-meta">${m.ts}</div>
        </div>`).join('');
    area.scrollTop = area.scrollHeight;
}

// ── Send ───────────────────────────────────────────────────────────────────
async function sendMessage() {
    const inp = $('compose-input');
    const txt = inp.value.trim();
    if (!txt || !S.active || !S.apiKey) return;
    const btn = $('send-btn');
    btn.disabled = true;
    inp.value = ''; inp.style.height = 'auto';

    // 1. Encrypt via ChaosKey
    const {ok, data} = await api('/v1/encrypt', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + S.apiKey },
        body: JSON.stringify({ plaintext: txt })
    });

    if (!ok) {
        alert('Encryption failed: ' + (data.error||'unknown error'));
        inp.value = txt; btn.disabled = false; return;
    }

    // 2. Store on server
    await api('/api/send', {
        method: 'POST',
        body: JSON.stringify({
            sender: S.myEmail, recipient: S.active,
            payload: { from:S.myEmail, plaintext:txt, ciphertext:data.ciphertext, nonce:data.nonce, encryption_key:data.encryption_key }
        })
    });

    // 3. Show immediately (optimistic)
    (S.messages[S.active]=S.messages[S.active]||[]).push({
        from: S.myEmail, text: txt, cipher: data.ciphertext,
        ts: new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})
    });
    renderMessages();
    btn.disabled = false;
}

// ── Burn ───────────────────────────────────────────────────────────────────
async function burnThread() {
    if (!S.active) return;
    if (!confirm(`Permanently delete your thread with ${S.active}?`)) return;
    await api('/api/delete_messages', {method:'POST', body:JSON.stringify({user:S.myEmail,contact:S.active})});
    S.messages[S.active] = [];
    renderMessages();
}

// ── Polling ────────────────────────────────────────────────────────────────
function startPolling() { stopPolling(); state_pollTimer = setInterval(loadMessages, 3000); S.pollTimer = state_pollTimer; }
function stopPolling()  { if (S.pollTimer) { clearInterval(S.pollTimer); S.pollTimer=null; } }

async function loadMessages() {
    if (!S.active || !S.myEmail || !S.apiKey) return;
    const {ok, data} = await api(`/api/get_messages?user=${encodeURIComponent(S.myEmail)}&contact=${encodeURIComponent(S.active)}`);
    if (!ok || !Array.isArray(data)) return;

    const decoded = await Promise.all(data.map(async row => {
        let p; try { p = typeof row.payload==='string' ? JSON.parse(row.payload) : row.payload; } catch { return null; }
        if (p.from===S.myEmail) return { from:p.from, text:p.plaintext, cipher:p.ciphertext, ts:shortTs(row.timestamp) };
        const {ok:dok, data:dd} = await api('/v1/decrypt', {
            method:'POST', headers:{ Authorization:'Bearer '+S.apiKey },
            body: JSON.stringify({ ciphertext:p.ciphertext, nonce:p.nonce, encryption_key:p.encryption_key })
        });
        return { from:p.from, text:dok?dd.plaintext:'[Decryption failed]', cipher:p.ciphertext, ts:shortTs(row.timestamp) };
    }));

    const valid = decoded.filter(Boolean);
    const prev  = S.messages[S.active]||[];
    if (valid.length > prev.length && document.hidden) {
        const newIncoming = valid.slice(prev.length).filter(m=>m.from!==S.myEmail).length;
        if (newIncoming) { S.unread[S.active]=(S.unread[S.active]||0)+newIncoming; renderContacts(); }
    }
    S.messages[S.active] = valid;
    renderMessages();
}

document.addEventListener('visibilitychange', () => {
    if (!document.hidden && S.active) { S.unread[S.active]=0; renderContacts(); }
});
</script>
</body>
</html>"""


@app.route("/chat")
def burnchat():
    return render_template_string(BURNCHAT_HTML)


# ════════════════════════════════════════════════════════════════
#  MAIN DASHBOARD  (served at /)
# ════════════════════════════════════════════════════════════════

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ChaosKey — Encryption from Physical Entropy</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:ital,wght@0,300;0,400;0,500;1,400&family=Instrument+Serif:ital@0;1&family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--ink:#08090c;--ink2:#0f1117;--ink3:#161b26;--line:#1e2535;--line2:#252d3e;--dust:#384158;--mist:#5a6a8a;--fog:#8898b8;--paper:#c5cede;--white:#eef2fb;--lime:#b8f552;--lime2:#d4ff7a;--lime3:rgba(184,245,82,.12);--teal:#52e5c8;--rose:#ff6b8a;--glow-lime:0 0 40px rgba(184,245,82,.25)}
html{scroll-behavior:smooth;-webkit-font-smoothing:antialiased}
body{background:var(--ink);color:var(--paper);font-family:'Outfit',sans-serif;font-weight:400;min-height:100vh;overflow-x:hidden}
::selection{background:var(--lime);color:#000}
#entropy-canvas{position:fixed;inset:0;width:100%;height:100%;pointer-events:none;z-index:0;opacity:.45}
.wrap{position:relative;z-index:1;max-width:1080px;margin:0 auto;padding:0 2rem}
nav{display:flex;align-items:center;justify-content:space-between;padding:1.4rem 2.5rem;position:sticky;top:0;z-index:100;background:rgba(8,9,12,.8);backdrop-filter:blur(20px);border-bottom:1px solid var(--line)}
.nav-logo{display:flex;align-items:center;gap:.75rem;font-family:'DM Mono',monospace;font-size:.95rem;color:var(--white);font-weight:500;text-decoration:none}
.logo-hex{width:34px;height:34px;background:linear-gradient(135deg,var(--lime),var(--teal));clip-path:polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%);display:flex;align-items:center;justify-content:center;font-size:15px;flex-shrink:0}
.nav-right{display:flex;align-items:center;gap:.75rem}
.nav-status{display:flex;align-items:center;gap:.5rem;font-family:'DM Mono',monospace;font-size:.72rem;color:var(--mist);padding:.35rem .9rem;border:1px solid var(--line2);border-radius:100px}
.nav-status.live{color:var(--lime);border-color:rgba(184,245,82,.3)}
.pulse-dot{width:6px;height:6px;border-radius:50%;background:var(--dust)}
.pulse-dot.live{background:var(--lime);box-shadow:0 0 8px var(--lime);animation:blink 2s ease-in-out infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.4}}
.nav-chat-btn{font-family:'DM Mono',monospace;font-size:.72rem;color:var(--lime);padding:.35rem .9rem;border:1px solid rgba(184,245,82,.3);border-radius:100px;background:rgba(184,245,82,.06);cursor:pointer;text-decoration:none;transition:all .2s}
.nav-chat-btn:hover{background:rgba(184,245,82,.15)}
.hero{padding:7rem 0 5rem;text-align:center}
.hero-eyebrow{display:inline-flex;align-items:center;gap:.6rem;font-family:'DM Mono',monospace;font-size:.72rem;color:var(--lime);letter-spacing:.12em;text-transform:uppercase;padding:.4rem 1.1rem;border:1px solid rgba(184,245,82,.25);border-radius:100px;background:rgba(184,245,82,.06);margin-bottom:2.5rem}
h1{font-family:'Instrument Serif',serif;font-size:clamp(3.2rem,7.5vw,6rem);line-height:1.02;letter-spacing:-.03em;color:var(--white);margin-bottom:1.75rem;font-weight:400}
h1 em{font-style:italic;background:linear-gradient(125deg,var(--lime) 0%,var(--teal) 55%,var(--lime2) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.hero-lead{font-size:1.1rem;line-height:1.75;color:var(--mist);max-width:560px;margin:0 auto 3.5rem;font-weight:300}
.hero-cta{display:flex;gap:1rem;justify-content:center;flex-wrap:wrap;margin-bottom:3rem}
.cta-primary{display:inline-flex;align-items:center;gap:.5rem;padding:.9rem 2rem;background:var(--lime);color:#000;border:none;border-radius:10px;font-family:'Outfit',sans-serif;font-weight:700;font-size:1rem;cursor:pointer;text-decoration:none;transition:background .2s,transform .15s}
.cta-primary:hover{background:var(--lime2);transform:translateY(-2px)}
.cta-ghost{display:inline-flex;align-items:center;gap:.5rem;padding:.9rem 2rem;background:none;color:var(--white);border:1px solid var(--line2);border-radius:10px;font-family:'Outfit',sans-serif;font-weight:500;font-size:1rem;text-decoration:none;transition:all .2s}
.cta-ghost:hover{border-color:var(--fog)}
.stats-row{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:var(--line);border:1px solid var(--line);border-radius:16px;overflow:hidden;margin:4rem 0}
.stat-cell{background:var(--ink2);padding:2rem;text-align:center}
.stat-n{font-family:'Instrument Serif',serif;font-size:2.8rem;color:var(--white);line-height:1;margin-bottom:.4rem}
.stat-l{font-size:.75rem;color:var(--mist);text-transform:uppercase;letter-spacing:.08em}
footer{border-top:1px solid var(--line);padding:2.5rem;display:flex;align-items:center;justify-content:space-between;color:var(--dust);font-size:.8rem;flex-wrap:wrap;gap:1rem}
@media(max-width:600px){h1{font-size:2.8rem}.stats-row{grid-template-columns:1fr}nav{padding:1rem 1.25rem}}
</style>
</head>
<body>
<canvas id="entropy-canvas"></canvas>
<nav>
  <a href="/" class="nav-logo"><div class="logo-hex">⬡</div>ChaosKey</a>
  <div class="nav-right">
    <div class="nav-status" id="nav-pill"><div class="pulse-dot" id="nav-dot"></div><span id="nav-txt">checking…</span></div>
    <a href="/chat" class="nav-chat-btn">🔥 BurnChat</a>
  </div>
</nav>
<div class="wrap">
  <section class="hero">
    <div class="hero-eyebrow">◈ Physical Entropy · AES-256-GCM · 10s Key Rotation</div>
    <h1>Your encryption key<br>born from <em>real chaos</em></h1>
    <p class="hero-lead">A camera watches a moving pendulum. A microphone listens to the room.<br><strong>That unpredictable motion derives a NEW cryptographic key every 10 seconds</strong> — generated locally, never stored in the cloud.</p>
    <div class="hero-cta">
      <a href="/chat" class="cta-primary">🔥 Open BurnChat →</a>
    </div>
  </section>
  <div class="stats-row">
    <div class="stat-cell"><div class="stat-n" id="s-customers">—</div><div class="stat-l">Active users</div></div>
    <div class="stat-cell"><div class="stat-n" id="s-today">—</div><div class="stat-l">Encryptions today</div></div>
    <div class="stat-cell"><div class="stat-n">10s</div><div class="stat-l">Key Rotation Rate</div></div>
  </div>
</div>
<footer>
  <div style="display:flex;align-items:center;gap:.75rem"><div class="logo-hex" style="width:24px;height:24px;font-size:11px">⬡</div><span style="font-family:'DM Mono',monospace;font-size:.75rem;color:var(--dust)">ChaosKey</span></div>
  <span style="font-family:'DM Mono',monospace;font-size:.65rem;color:var(--line2)">Physical entropy. Key never leaves your machine.</span>
</footer>
<script>
(function(){const cv=document.getElementById('entropy-canvas');const cx=cv.getContext('2d');let W,H,P=[];function resize(){W=cv.width=innerWidth;H=cv.height=innerHeight}resize();addEventListener('resize',resize);class Particle{constructor(){this.reset(true)}reset(i){this.x=Math.random()*W;this.y=i?Math.random()*H:(Math.random()<.5?-4:H+4);this.vx=(Math.random()-.5)*.4;this.vy=(Math.random()*.6+.2)*.4*(this.y<0?1:-1);this.r=Math.random()*1.5+.4;this.life=0;this.maxLife=300+Math.random()*400;this.hue=Math.random()<.6?150:175}step(){const t=Date.now()*.0003,nx=this.x/W*4+t,ny=this.y/H*4+t*.7,a=(Math.sin(nx)*Math.cos(ny))*Math.PI*2;this.vx+=Math.cos(a)*.008;this.vy+=Math.sin(a)*.008;this.vx*=.98;this.vy*=.98;this.x+=this.vx;this.y+=this.vy;this.life++;if(this.life>this.maxLife||this.x<-10||this.x>W+10||this.y<-10||this.y>H+10)this.reset(false)}draw(){const a=Math.min(this.life/60,1)*Math.min((this.maxLife-this.life)/60,1)*.6;cx.beginPath();cx.arc(this.x,this.y,this.r,0,Math.PI*2);cx.fillStyle=`hsla(${this.hue},90%,65%,${a})`;cx.fill()}}
for(let i=0;i<90;i++)P.push(new Particle());function draw(){cx.clearRect(0,0,W,H);for(let i=0;i<P.length;i++)for(let j=i+1;j<P.length;j++){const dx=P[i].x-P[j].x,dy=P[i].y-P[j].y,d=Math.sqrt(dx*dx+dy*dy);if(d<120){cx.beginPath();cx.moveTo(P[i].x,P[i].y);cx.lineTo(P[j].x,P[j].y);cx.strokeStyle=`rgba(184,245,82,${(1-d/120)*.07})`;cx.lineWidth=.5;cx.stroke()}}P.forEach(p=>{p.step();p.draw()});requestAnimationFrame(draw)}draw()})();
async function poll(){try{const d=await(await fetch('/health')).json(),dot=document.getElementById('nav-dot'),pill=document.getElementById('nav-pill'),txt=document.getElementById('nav-txt');if(d.tunnel_active){dot.classList.add('live');pill.classList.add('live');txt.textContent='Engine online'}else{dot.classList.remove('live');pill.classList.remove('live');txt.textContent='Engine offline'}const s=await(await fetch('/public/stats')).json();document.getElementById('s-customers').textContent=s.total_customers??'—';document.getElementById('s-today').textContent=s.today_requests??'—'}catch(e){}}
poll();setInterval(poll,6000);
</script>
</body>
</html>"""


@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


# ── Boot ──────────────────────────────────────────────────────────────────────
try:
    init_db()
except Exception as e:
    log.error(f"CRITICAL: Database initialization failed: {e}")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
