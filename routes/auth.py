from flask import Blueprint, request, jsonify, session

from db import db_exec, db_commit
from security import hash_password, check_password
from helpers import now_iso, pick_color, require_login, user_row

bp = Blueprint("auth", __name__, url_prefix="/auth")


@bp.route("/signup", methods=["POST"])
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
            (email, name, hash_password(pw), now_iso(), color, ck_key, public_key, enc_priv, vault_salt),
        )
        db_commit()
    except Exception as e:
        if "unique" in str(e).lower():
            return jsonify({"error": "Email already registered"}), 409
        return jsonify({"error": str(e)}), 500

    session["user_email"] = email
    session["user_name"]  = name
    session["user_color"] = color
    session["ck_key"]     = ck_key
    return jsonify({
        "ok": True, "email": email, "name": name, "color": color,
        "key_prefix": ck_key[:16] + "…", "has_ck_key": True,
        "public_key": public_key,
        "encrypted_private_key": enc_priv,
        "vault_salt": vault_salt,
    }), 201


@bp.route("/login", methods=["POST"])
def login():
    body  = request.get_json(force=True) or {}
    email = body.get("email", "").strip().lower()
    pw    = body.get("password", "").strip()

    if not email or not pw:
        return jsonify({"error": "Email and password required"}), 400

    user = user_row(email)
    if not user or not check_password(pw, user["password_hash"]):
        return jsonify({"error": "Invalid email or password"}), 401

    ck_key = user["chaoskey_api_key"] or ""
    session["user_email"] = user["email"]
    session["user_name"]  = user["display_name"]
    session["user_color"] = user["avatar_color"]
    session["ck_key"]     = ck_key
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


@bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


@bp.route("/me", methods=["GET"])
def me():
    if "user_email" not in session:
        return jsonify({"authenticated": False}), 200
    user = user_row(session["user_email"])
    ck_key = user["chaoskey_api_key"] if user else ""
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


@bp.route("/update_ck_key", methods=["POST"])
@require_login
def update_ck_key():
    body   = request.get_json(force=True) or {}
    ck_key = body.get("chaoskey_api_key", "").strip()
    if not ck_key or not ck_key.startswith("ck_live_"):
        return jsonify({"error": "Valid ChaosKey API key required"}), 400
    db_exec("UPDATE users SET chaoskey_api_key = ? WHERE email = ?", (ck_key, session["user_email"]))
    db_commit()
    session["ck_key"] = ck_key
    return jsonify({"ok": True, "key_prefix": ck_key[:16] + "…"})


@bp.route("/rekey", methods=["POST"])
@require_login
def rekey():
    body       = request.get_json(force=True) or {}
    pw         = body.get("password", "").strip()
    pub        = body.get("public_key", "").strip()
    enc_priv   = body.get("encrypted_private_key", "").strip()
    vault_salt = body.get("vault_salt", "").strip()

    if not pw or not pub or not enc_priv or not vault_salt:
        return jsonify({"error": "password, public_key, encrypted_private_key, vault_salt required"}), 400

    user = db_exec("SELECT password_hash FROM users WHERE email = ?", (session["user_email"],)).fetchone()
    if not user or not check_password(pw, user["password_hash"]):
        return jsonify({"error": "Incorrect password"}), 403

    db_exec(
        "UPDATE users SET public_key=?, encrypted_private_key=?, vault_salt=? WHERE email=?",
        (pub, enc_priv, vault_salt, session["user_email"]),
    )
    db_commit()
    return jsonify({"ok": True})


@bp.route("/change_password", methods=["POST"])
@require_login
def change_password():
    body       = request.get_json(force=True) or {}
    old_pw     = body.get("old_password", "").strip()
    new_pw     = body.get("new_password", "").strip()
    enc_priv   = body.get("encrypted_private_key", "").strip()
    vault_salt = body.get("vault_salt", "").strip()

    if not old_pw or not new_pw or not enc_priv or not vault_salt:
        return jsonify({"error": "old_password, new_password, encrypted_private_key, vault_salt required"}), 400
    if len(new_pw) < 6:
        return jsonify({"error": "New password must be at least 6 characters"}), 400

    user = db_exec("SELECT password_hash FROM users WHERE email = ?", (session["user_email"],)).fetchone()
    if not user or not check_password(old_pw, user["password_hash"]):
        return jsonify({"error": "Incorrect current password"}), 403

    db_exec(
        "UPDATE users SET password_hash=?, encrypted_private_key=?, vault_salt=? WHERE email=?",
        (hash_password(new_pw), enc_priv, vault_salt, session["user_email"]),
    )
    db_commit()
    return jsonify({"ok": True})
