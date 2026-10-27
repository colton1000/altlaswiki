# AtlasWiki v3

## Local run
```bash
pip install -r requirements.txt
python app.py
```
Open `http://127.0.0.1:5000`.

## Host the backend on the internet
The server now binds to `0.0.0.0` and reads `PORT`, so it works on Render, Railway, Fly.io, or another WSGI host.

Production start command:
```bash
gunicorn app:app
```

Set environment variables:
```text
FRONTEND_ORIGINS=https://www.your-frontend.example,https://your-frontend.example
DATABASE_PATH=/persistent-data/wiki.db
BANNED_WORDS=anotherword,another phrase
```
Use a persistent disk for `DATABASE_PATH`; otherwise SQLite data may disappear after a redeploy.

To host `index.html` on another website, change this line in its `<head>`:
```html
<meta name="atlas-api" content="https://your-python-backend.example">
```
The backend only grants browser CORS access to exact origins listed in `FRONTEND_ORIGINS`. Do not use `*` for a public write API.

## Team comment moderation
The first page created for a team establishes its moderation key. Later page creation for that team requires the same key. A team's **Team delete** button deletes a comment only when that key is supplied. Keys are PBKDF2-hashed in SQLite rather than stored as plain text.

Because there are still no accounts, protect and share each team key privately. Losing it currently requires a database administrator to reset it.

## Word filtering
Edit `banned_words.txt` or set `BANNED_WORDS`. The backend checks usernames, page text, tags, team names, and comments. Backend validation is authoritative, so bypassing browser JavaScript does not bypass the filter.
