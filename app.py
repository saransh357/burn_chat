import logging

from flask import Flask
from flask_cors import CORS

from config import SECRET_KEY, PORT
from db import init_db, close_db
from routes import auth, proxy, keys, messages, misc

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("BurnChat")


def create_app():
    app = Flask("BurnChat")
    app.secret_key = SECRET_KEY

    # NOTE: supports_credentials=True + an open CORS policy is dangerous —
    # see SECURITY.md. Lock ALLOWED_ORIGINS down for any real deployment.
    CORS(app, supports_credentials=True)

    app.register_blueprint(auth.bp)
    app.register_blueprint(proxy.bp)
    app.register_blueprint(keys.bp)
    app.register_blueprint(messages.bp)
    app.register_blueprint(misc.bp)

    app.teardown_appcontext(close_db)

    try:
        init_db(app)
    except Exception as e:
        log.error(f"DB init failed: {e}")

    return app


app = create_app()

if __name__ == "__main__":
    log.info(f"BurnChat starting on port {PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
