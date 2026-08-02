"""
Central configuration for BurnChat, read once from the environment.
Keeping this in its own module means every other module imports
constants instead of re-reading os.environ (and makes testing/overriding
trivial — just monkeypatch config.* before the app is created).
"""
import os
import secrets

CHAOSKEY_URL = os.getenv("CHAOSKEY_URL", "https://api.chaoskey.com").rstrip("/")
SECRET_KEY   = os.getenv("SECRET_KEY", secrets.token_hex(32))
DATABASE_URL = os.getenv("DATABASE_URL", "")
DB_PATH      = os.getenv("DB_PATH", "burnchat.db")
PORT         = int(os.getenv("PORT", 5000))
USE_POSTGRES = bool(DATABASE_URL)

# NOTE: if SECRET_KEY is not set explicitly, a new random one is generated
# on every process start. That's fine for a single dev instance, but in
# production (especially with multiple workers/processes, or restarts)
# it invalidates every existing session and, more importantly, must be
# set explicitly and kept secret — see SECURITY.md.
