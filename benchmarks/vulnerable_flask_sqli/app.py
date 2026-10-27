import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)


def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, role TEXT, secret TEXT)")
    cursor.execute("DELETE FROM users")
    cursor.execute("INSERT INTO users (username, role, secret) VALUES ('alice', 'user', 'alice_secret_123')")
    cursor.execute("INSERT INTO users (username, role, secret) VALUES ('admin', 'administrator', 'FLAG{admin_super_secret_token}')")
    conn.commit()
    conn.close()


@app.route("/user", methods=["GET"])
def get_user():
    username = request.args.get("username", "")
    if not username:
        return jsonify({"error": "Missing username parameter"}), 400

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    
    # Flaw: Raw SQL string formatting vulnerable to SQL Injection (CWE-89 / OWASP A03:2021)
    query = f"SELECT username, role FROM users WHERE username = '{username}'"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()

    if user:
        return jsonify({"username": user[0], "role": user[1]}), 200
    return jsonify({"error": "User not found"}), 404


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
