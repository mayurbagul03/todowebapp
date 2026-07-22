import os
import psycopg2
from dotenv import load_dotenv
from flask import Flask, send_from_directory, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash

# load_dotenv("key.env")   # without this, key.env is never read!
load_dotenv(os.path.join(os.path.dirname(__file__), "key.env"))

app = Flask(__name__, static_folder="../frontend",static_url_path="")
def get_db():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5434"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", ""),
        dbname=os.getenv("DB_NAME", "todo"),
    )

@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify(error="Enter username and password"), 400

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT user_id, first_name, password_hash FROM users WHERE username = %s",
                (username,),
            )
            row = cur.fetchone()
    finally:
        conn.close()

    if row is None or not check_password_hash(row[2], password):
        return jsonify(error="Invalid username or password"), 401

    session["user_id"] = row[0]          # this is the "remember me" moment
    return jsonify(user_id=row[0], first_name=row[1])

@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    first_name = (data.get("first_name") or "").strip()
    last_name  = (data.get("last_name") or "").strip()
    username   = (data.get("username") or "").strip().lower()
    password   = data.get("password") or ""

    if not first_name or not last_name or not username or not password:
        return jsonify(error="All fields are required"), 400
    if len(password) < 6:
        return jsonify(error="Password must be at least 6 characters"), 400

    conn = get_db()                          # ← indented: inside the function
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT user_id FROM users WHERE username = %s", (username,))
            if cur.fetchone():
                return jsonify(error="Username already exists. Please login."), 409

            cur.execute(
                """INSERT INTO users (first_name, last_name, username, password_hash)
                   VALUES (%s, %s, %s, %s)
                   RETURNING user_id""",
                (first_name, last_name, username, generate_password_hash(password)),
            )
            new_id = cur.fetchone()[0]
        conn.commit()
        return jsonify(user_id=new_id, username=username), 201
    finally:
        conn.close()

@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(message="Logged out")

@app.get("/api/me")
def me():
    user_id = session.get("user_id")
    if user_id is None:
        return jsonify(error="Not logged in"), 401
    return jsonify(user_id=user_id)

@app.get("/")
def index():
    return send_from_directory(app.static_folder, "login.html")

if __name__ == "__main__":
    app.run(debug=True, port=5000)