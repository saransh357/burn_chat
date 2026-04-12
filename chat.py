from flask import Flask, render_template_string, request, jsonify
import os, sqlite3, json
from datetime import datetime

app = Flask(__name__)
DB_PATH = "chat_store.db"

def init_chat_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''CREATE TABLE IF NOT EXISTS messages 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                     sender TEXT, recipient TEXT, 
                     payload TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    with open('chat.html', 'r') as f:
        return render_template_string(f.read())

@app.route('/api/send', methods=['POST'])
def send_msg():
    data = request.json
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO messages (sender, recipient, payload) VALUES (?, ?, ?)",
                 (data['sender'], data['recipient'], json.dumps(data['payload'])))
    conn.commit()
    conn.close()
    return jsonify({"status": "sent"})

@app.route('/api/get_messages', methods=['GET'])
def get_msgs():
    user = request.args.get('user')
    contact = request.args.get('contact')
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Fetch messages where you are the sender or the recipient
    rows = conn.execute("""SELECT * FROM messages WHERE 
                           (sender=? AND recipient=?) OR (sender=? AND recipient=?) 
                           ORDER BY timestamp ASC""", (user, contact, contact, user)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

if __name__ == "__main__":
    init_chat_db()
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 8000)))
