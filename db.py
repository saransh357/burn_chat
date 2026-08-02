"""
Database abstraction. Supports SQLite (default, WAL mode for concurrent
read/write) or Postgres (if DATABASE_URL is set), behind a single
db_exec()/db_commit() interface so route code never branches on backend.
"""
import sqlite3
import urllib.parse as _up

from flask import g

from config import DATABASE_URL, DB_PATH, USE_POSTGRES

# ── Schema ────────────────────────────────────────────────────────────────
SCHEMA_SQLITE = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS users (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    email                 TEXT UNIQUE NOT NULL,
    display_name          TEXT NOT NULL,
    password_hash         TEXT NOT NULL,
    created_at            TEXT NOT NULL,
    avatar_color          TEXT NOT NULL DEFAULT '#ff6b35',
    chaoskey_api_key      TEXT,
    public_key            TEXT,
    encrypted_private_key TEXT,
    vault_salt            TEXT
);
CREATE TABLE IF NOT EXISTS messages (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sender          TEXT NOT NULL,
    recipient       TEXT NOT NULL,
    ciphertext      TEXT NOT NULL,
    nonce           TEXT NOT NULL DEFAULT '',
    enc_key         TEXT NOT NULL DEFAULT '',
    sender_enc_key  TEXT NOT NULL DEFAULT '',
    sent_at         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_msg_thread_cov
    ON messages(sender, recipient, id, ciphertext, nonce, enc_key, sender_enc_key, sent_at);
CREATE INDEX IF NOT EXISTS idx_msg_id ON messages(id);
CREATE INDEX IF NOT EXISTS idx_msg_sender    ON messages(sender);
CREATE INDEX IF NOT EXISTS idx_msg_recipient ON messages(recipient);
"""

SCHEMA_PG_STMTS = [
    """CREATE TABLE IF NOT EXISTS users (
        id                    SERIAL PRIMARY KEY,
        email                 TEXT UNIQUE NOT NULL,
        display_name          TEXT NOT NULL,
        password_hash         TEXT NOT NULL,
        created_at            TEXT NOT NULL,
        avatar_color          TEXT NOT NULL DEFAULT '#ff6b35',
        chaoskey_api_key      TEXT,
        public_key            TEXT,
        encrypted_private_key TEXT,
        vault_salt            TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS messages (
        id              SERIAL PRIMARY KEY,
        sender          TEXT NOT NULL,
        recipient       TEXT NOT NULL,
        ciphertext      TEXT NOT NULL,
        nonce           TEXT NOT NULL DEFAULT '',
        enc_key         TEXT NOT NULL DEFAULT '',
        sender_enc_key  TEXT NOT NULL DEFAULT '',
        sent_at         TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_msg_thread_cov ON messages(sender, recipient, id)",
    "CREATE INDEX IF NOT EXISTS idx_msg_id ON messages(id)",
    "CREATE INDEX IF NOT EXISTS idx_msg_sender ON messages(sender)",
    "CREATE INDEX IF NOT EXISTS idx_msg_recipient ON messages(recipient)",
]

PG_MIGRATIONS = [
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_color TEXT NOT NULL DEFAULT '#ff6b35'",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS chaoskey_api_key TEXT",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS public_key TEXT",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS encrypted_private_key TEXT",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS vault_salt TEXT",
    "ALTER TABLE messages ADD COLUMN IF NOT EXISTS sender_enc_key TEXT NOT NULL DEFAULT ''",
]


def _pg_url():
    url = (DATABASE_URL or "").strip()
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    parsed = _up.urlparse(url)
    qs = _up.parse_qs(parsed.query)
    qs.pop("channel_binding", None)
    return _up.urlunparse(parsed._replace(query=_up.urlencode(qs, doseq=True)))


if USE_POSTGRES:
    import psycopg2
    import psycopg2.extras

    def get_db():
        if "db" not in g:
            g.db = psycopg2.connect(_pg_url())
            g.db.autocommit = False
        return g.db

    def db_exec(sql, params=()):
        sql = sql.replace("?", "%s")
        cur = get_db().cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql, params)
        return cur

    def db_commit():
        get_db().commit()

    def close_db(exc):
        db = g.pop("db", None)
        if db:
            db.rollback() if exc else db.commit()
            db.close()

else:
    def get_db():
        if "db" not in g:
            db = sqlite3.connect(DB_PATH, check_same_thread=False)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=NORMAL")
            db.execute("PRAGMA cache_size=-16000")   # 16 MB page cache
            db.execute("PRAGMA temp_store=MEMORY")
            g.db = db
        return g.db

    def db_exec(sql, params=()):
        return get_db().execute(sql, params)

    def db_commit():
        get_db().commit()

    def close_db(exc=None):
        db = g.pop("db", None)
        if db:
            db.close()


def init_db(app):
    """Create tables/indexes and run additive migrations. Safe to call on
    every startup — every statement is IF NOT EXISTS / best-effort."""
    with app.app_context():
        if USE_POSTGRES:
            conn = psycopg2.connect(_pg_url())
            conn.autocommit = True
            cur = conn.cursor()
            for stmt in SCHEMA_PG_STMTS + PG_MIGRATIONS:
                try:
                    cur.execute(stmt)
                except Exception as e:
                    app.logger.warning(f"Migration skipped: {e}")
            conn.close()
        else:
            db = sqlite3.connect(DB_PATH)
            db.executescript(SCHEMA_SQLITE)
            for col, default in [
                ("avatar_color",          "'#ff6b35'"),
                ("chaoskey_api_key",      "NULL"),
                ("public_key",            "NULL"),
                ("encrypted_private_key", "NULL"),
                ("vault_salt",            "NULL"),
            ]:
                try:
                    db.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT NOT NULL DEFAULT {default}")
                    db.commit()
                except Exception:
                    pass
            try:
                db.execute("ALTER TABLE messages ADD COLUMN sender_enc_key TEXT NOT NULL DEFAULT ''")
                db.commit()
            except Exception:
                pass
            db.commit()
            db.close()
    app.logger.info("Database ready.")
