from flask import Blueprint, jsonify, render_template

from config import CHAOSKEY_URL, USE_POSTGRES

bp = Blueprint("misc", __name__)


@bp.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "chaoskey_url": CHAOSKEY_URL,
        "db_backend": "postgresql" if USE_POSTGRES else "sqlite+WAL",
        "e2ee": "ChaosKey AES-256-GCM (proxied) + RSA-OAEP dual-wrap (browser)",
        "speed": "incremental polling + optimistic send + speculative encrypt + keepalive CK pool + N+1 fix",
    })


@bp.route("/")
def index():
    return render_template("index.html")
