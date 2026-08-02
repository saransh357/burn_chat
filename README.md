# BurnChat  split 

Originally a single 2k line `app.py` with the entire backend, HTML,
CSS, and JS embedded as a Python string. Same behavior, same routes,
same DB schema  just organized so each concern lives in its own file.

## Layout

```
burnchat/
├── app.py                 # Flask app factory + entry point (python app.py)
├── config.py               # env-var config (CHAOSKEY_URL, SECRET_KEY, DB_*, PORT)
├── security.py              # password hashing (bcrypt, with fallback)
├── chaoskey_client.py        # keep-alive HTTP client for the ChaosKey API
├── db.py                     # SQLite/Postgres abstraction + schema + migrations
├── helpers.py                # shared route helpers (require_login, user_row, ...)
├── routes/
│   ├── auth.py               # /auth/* — signup, login, logout, rekey, ...
│   ├── proxy.py               # /proxy/* — ChaosKey encrypt/decrypt relay
│   ├── keys.py                 # /user/* — public key lookup/update
│   ├── messages.py              # /msg/* — send, thread, inbox, burn, search
│   └── misc.py                   # /health, / (index page)
├── templates/
│   └── index.html                # page markup 
├── static/
│   ├── css/style.css               # was an inline <style> block
│   └── js/app.js                    # was an inline <script> block
├── requirements.txt
└── SECURITY.md               # security review — read this
```

## Running it

```bash
pip install -r requirements.txt
python app.py            # http://localhost:5000, SQLite by default
```

Set `DATABASE_URL` to use Postgres instead of SQLite, `SECRET_KEY` to
pin the Flask session signing key (**do this before deploying** — see
SECURITY.md item 7), and `CHAOSKEY_URL`/`PORT` as needed.

