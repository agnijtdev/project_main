from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)


def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS accounts (id INTEGER PRIMARY KEY, username TEXT, role TEXT)")
    cursor.execute("DELETE FROM accounts")
    cursor.execute("INSERT INTO accounts (username, role) VALUES ('alice', 'developer')")
    cursor.execute("INSERT INTO accounts (username, role) VALUES ('admin', 'superadmin')")
    conn.commit()
    conn.close()


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy"}), 200


if __name__ == "__main__":
    init_db()
    app.run(port=5000)
