"""
Password hashing helpers, isolated so the rest of the app never touches
a raw password or a hashing primitive directly.

Prefers bcrypt (adaptive, salted, industry standard for password storage).
Falls back to a salted SHA-256 scheme ONLY if the bcrypt package isn't
installed — see SECURITY.md for why that fallback is weaker and should
not be relied on in production.
"""
import hmac
import secrets
import hashlib as _hl

try:
    import bcrypt as _bcrypt
    _HAS_BCRYPT = True

    def hash_password(pw: str) -> str:
        return _bcrypt.hashpw(pw.encode(), _bcrypt.gensalt(12)).decode()

    def check_password(pw: str, h: str) -> bool:
        return _bcrypt.checkpw(pw.encode(), h.encode())

except ImportError:
    _HAS_BCRYPT = False

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
