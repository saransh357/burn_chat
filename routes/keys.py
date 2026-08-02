from flask import Blueprint, request, jsonify, session

from db import db_exec, db_commit
from helpers import require_login

bp = Blueprint("keys", __name__, url_prefix="/user")


@bp.route("/key", methods=["GET"])
@require_login
def get_user_key():
    email = request.args.get("email", "").strip().lower()
    if not email:
        return jsonify({"error": "email param required"}), 400
    u = db_exec("SELECT public_key FROM users WHERE email = ?", (email,)).fetchone()
    return jsonify({"key": u["public_key"] if u else None})


@bp.route("/keys_bulk", methods=["POST"])
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


@bp.route("/update_key", methods=["POST"])
@require_login
def update_public_key():
    body = request.get_json(force=True) or {}
    pub  = body.get("public_key", "").strip()
    if not pub:
        return jsonify({"error": "public_key required"}), 400
    db_exec("UPDATE users SET public_key = ? WHERE email = ?", (pub, session["user_email"]))
    db_commit()
    return jsonify({"ok": True})
