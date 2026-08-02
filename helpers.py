"""Small helpers shared across route modules."""
from datetime import datetime, timezone
from functools import wraps

from flask import jsonify, session

from db import db_exec

AVATAR_COLORS = [
    "#ff6b35", "#f7931e", "#ffcd3c", "#4ecdc4",
    "#45b7d1", "#a29bfe", "#fd79a8", "#00b894",
]


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def pick_color(email):
    return AVATAR_COLORS[sum(ord(c) for c in email) % len(AVATAR_COLORS)]


def require_login(f):
    """Route decorator: 401s any request without a valid session.
    This is the only thing standing between the message/proxy/key
    endpoints and an anonymous caller — see SECURITY.md."""
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "user_email" not in session:
            return jsonify({"error": "Not authenticated"}), 401
        return f(*args, **kwargs)
    return wrapped


def get_user_ck_key(email):
    """Return the caller's ChaosKey API key, preferring the session cache
    (set at login) over a DB round-trip."""
    ck = session.get("ck_key")
    if ck:
        return ck
    user = db_exec("SELECT chaoskey_api_key FROM users WHERE email = ?", (email,)).fetchone()
    return (user["chaoskey_api_key"] or "") if user else ""


def user_row(email):
    return db_exec(
        "SELECT email, display_name, password_hash, avatar_color, chaoskey_api_key, "
        "public_key, encrypted_private_key, vault_salt FROM users WHERE email = ?",
        (email,),
    ).fetchone()
