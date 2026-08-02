from flask import Blueprint, request, jsonify, session

from db import db_exec, db_commit
from helpers import now_iso, require_login

bp = Blueprint("messages", __name__, url_prefix="/msg")


@bp.route("/send", methods=["POST"])
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
        (sender, recipient, ciphertext, nonce, rsa_enc_key, sender_enc_key, now_iso()),
    )
    db_commit()
    new_id = cur.lastrowid
    return jsonify({"ok": True, "id": new_id, "sent_at": now_iso()}), 201


@bp.route("/thread", methods=["GET"])
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
        (me, contact, contact, me, since),
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


@bp.route("/burn", methods=["POST"])
@require_login
def burn_thread():
    body    = request.get_json(force=True) or {}
    contact = body.get("contact", "").strip().lower()
    me      = session["user_email"]
    if not contact:
        return jsonify({"error": "contact required"}), 400
    db_exec(
        "DELETE FROM messages WHERE (sender=? AND recipient=?) OR (sender=? AND recipient=?)",
        (me, contact, contact, me),
    )
    db_commit()
    return jsonify({"ok": True, "burned": True})


@bp.route("/inbox", methods=["GET"])
@require_login
def inbox():
    """Single JOIN fetches contact display_name/avatar_color for every
    thread at once (previously one query per contact — N+1)."""
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
        (me, me, me, me),
    ).fetchall()
    return jsonify([{
        "contact": r["contact"],
        "name":    r["display_name"] or r["contact"].split("@")[0],
        "color":   r["avatar_color"] or "#888",
        "last_at": r["last_at"],
        "total":   r["total"],
    } for r in rows])


@bp.route("/search_user", methods=["GET"])
@require_login
def search_user():
    q = request.args.get("q", "").strip().lower()
    if not q or len(q) < 3:
        return jsonify([])
    rows = db_exec(
        "SELECT email, display_name, avatar_color FROM users "
        "WHERE (email LIKE ? OR display_name LIKE ?) AND email != ? LIMIT 10",
        (f"%{q}%", f"%{q}%", session["user_email"]),
    ).fetchall()
    return jsonify([{"email": r["email"], "name": r["display_name"], "color": r["avatar_color"]} for r in rows])
