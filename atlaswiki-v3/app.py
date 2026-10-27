"""AtlasWiki backend: usernames, team moderation, word filtering, and deployable CORS."""
from datetime import date, datetime, timezone
from pathlib import Path
from functools import wraps
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
from flask import Flask, jsonify, request, send_from_directory

BASE = Path(__file__).resolve().parent
DB = Path(os.getenv("DATABASE_PATH", str(BASE / "wiki.db")))
FRONTEND_ORIGINS = {x.strip().rstrip("/") for x in os.getenv("FRONTEND_ORIGINS", "http://localhost:5500,http://127.0.0.1:5500").split(",") if x.strip()}
DEFAULT_BLOCKED = {"spamword", "badword"}
app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 1_000_000


def connect():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def init_db():
    DB.parent.mkdir(parents=True, exist_ok=True)
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY COLLATE NOCASE,created_at TEXT NOT NULL,last_seen TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS teams(name TEXT PRIMARY KEY COLLATE NOCASE,moderator_hash TEXT NOT NULL,created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS pages(
          id INTEGER PRIMARY KEY AUTOINCREMENT,slug TEXT UNIQUE NOT NULL,title TEXT NOT NULL,language TEXT NOT NULL,
          team TEXT NOT NULL,tags TEXT NOT NULL DEFAULT '',summary TEXT NOT NULL,body TEXT NOT NULL,author TEXT,
          is_user_page INTEGER NOT NULL DEFAULT 1,updated TEXT NOT NULL,
          FOREIGN KEY(author) REFERENCES users(username),FOREIGN KEY(team) REFERENCES teams(name));
        CREATE TABLE IF NOT EXISTS comments(
          id INTEGER PRIMARY KEY AUTOINCREMENT,page_id INTEGER NOT NULL,username TEXT NOT NULL,body TEXT NOT NULL,created_at TEXT NOT NULL,
          FOREIGN KEY(page_id) REFERENCES pages(id) ON DELETE CASCADE,FOREIGN KEY(username) REFERENCES users(username));
        """)
        cols = {r[1] for r in db.execute("PRAGMA table_info(pages)")}
        if "author" not in cols: db.execute("ALTER TABLE pages ADD COLUMN author TEXT")
        if "is_user_page" not in cols: db.execute("ALTER TABLE pages ADD COLUMN is_user_page INTEGER NOT NULL DEFAULT 1")


def blocked_words():
    words = set(DEFAULT_BLOCKED)
    path = BASE / "banned_words.txt"
    if path.exists():
        words |= {line.strip().casefold() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")}
    words |= {x.strip().casefold() for x in os.getenv("BANNED_WORDS", "").split(",") if x.strip()}
    return words


def find_blocked(*values):
    text = " ".join(str(v or "") for v in values).casefold()
    return sorted(w for w in blocked_words() if re.search(rf"(?<!\w){re.escape(w)}(?!\w)", text))


def hash_key(key, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", key.encode(), bytes.fromhex(salt), 200_000).hex()
    return f"{salt}${digest}"


def verify_key(key, stored):
    try:
        salt, expected = stored.split("$", 1)
        actual = hash_key(key, salt).split("$", 1)[1]
        return hmac.compare_digest(actual, expected)
    except (ValueError, AttributeError):
        return False


def clean_username(value):
    value = str(value or "").strip()
    return value if re.fullmatch(r"[A-Za-z0-9_.-]{2,24}", value) else None


def ensure_user(db, username):
    now = datetime.now(timezone.utc).isoformat()
    db.execute("INSERT INTO users VALUES(?,?,?) ON CONFLICT(username) DO UPDATE SET last_seen=excluded.last_seen", (username, now, now))


def ensure_team(db, name, key):
    name, key = str(name or "").strip(), str(key or "")
    if not name or len(name) > 50 or len(key) < 8:
        return False, "Team name is required and the team moderation key must be at least 8 characters"
    row = db.execute("SELECT moderator_hash FROM teams WHERE name=?", (name,)).fetchone()
    if row and not verify_key(key, row["moderator_hash"]):
        return False, "Incorrect moderation key for this team"
    if not row:
        db.execute("INSERT INTO teams VALUES(?,?,?)", (name, hash_key(key), datetime.now(timezone.utc).isoformat()))
    return True, None


def page_dict(row):
    result = dict(row); result["tags"] = [t for t in result.get("tags", "").split(",") if t]; result["is_user_page"] = bool(result.get("is_user_page")); return result


@app.after_request
def cors(response):
    origin = request.headers.get("Origin", "").rstrip("/")
    if origin in FRONTEND_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "GET,POST,DELETE,OPTIONS"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.route("/api/<path:_>", methods=["OPTIONS"])
def options(_): return ("", 204)

@app.get("/")
def index(): return send_from_directory(BASE, "index.html")

@app.get("/api/config")
def config(): return jsonify(blocked_words=sorted(blocked_words()))

@app.post("/api/users")
def save_user():
    data = request.get_json(silent=True) or {}; username = clean_username(data.get("username"))
    if not username: return jsonify(error="Username must be 2-24 characters: letters, numbers, _, ., or -"), 400
    if find_blocked(username): return jsonify(error="Username contains a blocked word"), 400
    with connect() as db:
        ensure_user(db, username); row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    return jsonify(dict(row))

@app.get("/api/pages")
def pages():
    query, language, tag, team = (request.args.get(x, "").strip() for x in ("q", "lang", "tag", "team"))
    sql, args = "SELECT * FROM pages WHERE 1=1", []
    if query: sql += " AND (title LIKE ? OR summary LIKE ? OR body LIKE ? OR author LIKE ?)"; args += [f"%{query}%"] * 4
    if language: sql += " AND language=?"; args.append(language)
    if tag: sql += " AND ','||tags||',' LIKE ?"; args.append(f"%,{tag.lower()},%")
    if team: sql += " AND team LIKE ?"; args.append(f"%{team}%")
    with connect() as db: rows = db.execute(sql + " ORDER BY updated DESC,title", args).fetchall()
    return jsonify([page_dict(r) for r in rows])

@app.post("/api/pages")
def create_page():
    data = request.get_json(silent=True) or {}; username = clean_username(data.get("username"))
    if not username: return jsonify(error="Choose a valid username first"), 400
    required = ("title", "language", "team", "summary", "body")
    if any(not str(data.get(k, "")).strip() for k in required): return jsonify(error="title, language, team, summary and body are required"), 400
    hits = find_blocked(username, data.get("title"), data.get("team"), data.get("summary"), data.get("body"), " ".join(data.get("tags", [])))
    if hits: return jsonify(error="Blocked word detected", blocked_words=hits), 400
    slug = re.sub(r"[^a-z0-9]+", "-", data["title"].lower()).strip("-") or f"page-{int(datetime.now().timestamp())}"
    tags = ",".join(dict.fromkeys(str(t).strip().lower() for t in data.get("tags", []) if str(t).strip()))
    try:
        with connect() as db:
            ok, error = ensure_team(db, data["team"], data.get("team_key"))
            if not ok: return jsonify(error=error), 403
            ensure_user(db, username)
            cur = db.execute("INSERT INTO pages(slug,title,language,team,tags,summary,body,author,is_user_page,updated) VALUES(?,?,?,?,?,?,?,?,1,?)",
                (slug,data["title"].strip(),data["language"].strip(),data["team"].strip(),tags,data["summary"].strip(),data["body"].strip(),username,date.today().isoformat()))
            row = db.execute("SELECT * FROM pages WHERE id=?", (cur.lastrowid,)).fetchone()
        return jsonify(page_dict(row)), 201
    except sqlite3.IntegrityError: return jsonify(error="A page with that title already exists"), 409

@app.get("/api/pages/<int:page_id>/comments")
def get_comments(page_id):
    with connect() as db: rows = db.execute("SELECT * FROM comments WHERE page_id=? ORDER BY id DESC", (page_id,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.post("/api/pages/<int:page_id>/comments")
def add_comment(page_id):
    data = request.get_json(silent=True) or {}; username, body = clean_username(data.get("username")), str(data.get("body", "")).strip()
    if not username: return jsonify(error="Choose a valid username first"), 400
    if not body or len(body) > 1000: return jsonify(error="Comment must be 1-1000 characters"), 400
    hits = find_blocked(username, body)
    if hits: return jsonify(error="Blocked word detected", blocked_words=hits), 400
    with connect() as db:
        page = db.execute("SELECT is_user_page FROM pages WHERE id=?", (page_id,)).fetchone()
        if not page: return jsonify(error="Page not found"), 404
        if not page["is_user_page"]: return jsonify(error="Comments are only available on user-made pages"), 403
        ensure_user(db, username)
        cur = db.execute("INSERT INTO comments(page_id,username,body,created_at) VALUES(?,?,?,?)", (page_id,username,body,datetime.now(timezone.utc).isoformat()))
        row = db.execute("SELECT * FROM comments WHERE id=?", (cur.lastrowid,)).fetchone()
    return jsonify(dict(row)), 201

@app.delete("/api/pages/<int:page_id>/comments/<int:comment_id>")
def delete_comment(page_id, comment_id):
    data = request.get_json(silent=True) or {}; key = str(data.get("team_key", ""))
    with connect() as db:
        row = db.execute("SELECT c.id,p.team,t.moderator_hash FROM comments c JOIN pages p ON p.id=c.page_id JOIN teams t ON t.name=p.team WHERE c.id=? AND c.page_id=?", (comment_id,page_id)).fetchone()
        if not row: return jsonify(error="Comment not found"), 404
        if not verify_key(key, row["moderator_hash"]): return jsonify(error="Incorrect team moderation key"), 403
        db.execute("DELETE FROM comments WHERE id=?", (comment_id,))
    return jsonify(deleted=True, comment_id=comment_id)

init_db()
if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "0.0.0.0"), port=int(os.getenv("PORT", "5000")), debug=os.getenv("FLASK_DEBUG") == "1")
