import os
import psycopg2
from dotenv import load_dotenv
from flask import Flask, send_from_directory, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("user_id") is None:
            return jsonify(error="Not logged in"), 401
        return f(*args, **kwargs)
    return wrapper

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


@app.get("/api/todos")
@login_required
def list_todos():
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT id, title, completed, created_at
                   FROM todos WHERE user_id = %s
                   ORDER BY created_at""",
                (session["user_id"],),
            )
            todos = [
                {"id": r[0], "title": r[1], "completed": r[2], "created_at": r[3].isoformat()}
                for r in cur.fetchall()
            ]
    finally:
        conn.close()
    return jsonify(todos=todos)


@app.post("/api/todos")
@login_required
def add_todo():
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    if not title:
        return jsonify(error="Task can't be empty"), 400

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO todos (user_id, title)
                   VALUES (%s, %s)
                   RETURNING id, title, completed""",
                (session["user_id"], title),
            )
            row = cur.fetchone()
        conn.commit()
    finally:
        conn.close()
    return jsonify(todo={"id": row[0], "title": row[1], "completed": row[2]}), 201


@app.patch("/api/todos/<int:todo_id>")
@login_required
def toggle_todo(todo_id):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE todos SET completed = NOT completed
                   WHERE id = %s AND user_id = %s
                   RETURNING id, completed""",
                (todo_id, session["user_id"]),
            )
            row = cur.fetchone()
        conn.commit()
    finally:
        conn.close()
    if row is None:
        return jsonify(error="Task not found"), 404
    return jsonify(todo={"id": row[0], "completed": row[1]})


@app.delete("/api/todos/<int:todo_id>")
@login_required
def delete_todo(todo_id):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM todos WHERE id = %s AND user_id = %s RETURNING id",
                (todo_id, session["user_id"]),
            )
            row = cur.fetchone()
        conn.commit()
    finally:
        conn.close()
    if row is None:
        return jsonify(error="Task not found"), 404
    return jsonify(deleted=todo_id)

@app.get("/")
def index():
    return send_from_directory(app.static_folder, "login.html")

if __name__ == "__main__":
    app.run(debug=True, port=5000)