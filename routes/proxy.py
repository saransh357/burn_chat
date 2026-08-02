"""
Proxy endpoints. The browser calls these instead of ChaosKey directly so
the ChaosKey API key never leaves the server (see SECURITY.md).
"""
import logging

from flask import Blueprint, request, jsonify, session

from chaoskey_client import chaoskey_post
from helpers import require_login, get_user_ck_key

log = logging.getLogger("BurnChat")
bp = Blueprint("proxy", __name__, url_prefix="/proxy")


@bp.route("/encrypt", methods=["POST"])
@require_login
def proxy_encrypt():
    body   = request.get_json(force=True) or {}
    ck_key = get_user_ck_key(session["user_email"])
    if not ck_key:
        return jsonify({"error": "No ChaosKey API key on account"}), 400
    try:
        data, status = chaoskey_post("/v1/encrypt", {"plaintext": body.get("plaintext", "")}, ck_key)
        return jsonify(data), status
    except Exception as e:
        log.error(f"ChaosKey /v1/encrypt error: {e}")
        return jsonify({"error": str(e)}), 502


@bp.route("/decrypt", methods=["POST"])
@require_login
def proxy_decrypt():
    body   = request.get_json(force=True) or {}
    ck_key = get_user_ck_key(session["user_email"])
    if not ck_key:
        return jsonify({"error": "No ChaosKey API key on account"}), 400
    try:
        payload = {
            "ciphertext":     body.get("ciphertext", ""),
            "nonce":          body.get("nonce", ""),
            "encryption_key": body.get("encryption_key", ""),
        }
        data, status = chaoskey_post("/v1/decrypt", payload, ck_key)
        return jsonify(data), status
    except Exception as e:
        log.error(f"ChaosKey /v1/decrypt error: {e}")
        return jsonify({"error": str(e)}), 502
