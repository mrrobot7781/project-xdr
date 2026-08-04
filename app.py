
import os
import sqlite3
import secrets
from html import escape
from flask import Flask, request, redirect, render_template_string, g, session, abort

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
DATABASE = "todo.db"

HTML = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Secure To-Do</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{margin:0;font-family:Segoe UI,Arial;background:linear-gradient(135deg,#667eea,#764ba2);display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{width:90%;max-width:700px;background:rgba(255,255,255,.95);padding:30px;border-radius:20px;box-shadow:0 10px 30px rgba(0,0,0,.25)}
h1{text-align:center;color:#4b3ca7}
form.add{display:flex;gap:10px}
input[type=text]{flex:1;padding:12px;border-radius:10px;border:1px solid #ccc}
button{padding:12px 18px;border:none;border-radius:10px;background:#4b3ca7;color:#fff;cursor:pointer}
button:hover{background:#362a84}
ul{list-style:none;padding:0}
li{display:flex;justify-content:space-between;align-items:center;background:#f7f7f7;padding:12px;margin:10px 0;border-radius:10px}
.del{background:#d32f2f}
.del:hover{background:#b71c1c}
.small{color:#666;text-align:center}
.empty{text-align:center;color:#888;padding:25px}
</style>
</head>
<body>
<div class="card">
<h1>📝 Secure To‑Do List</h1>
<p class="small">Total Tasks: {{tasks|length}}</p>

<form class="add" method="POST" action="/add">
<input type="hidden" name="csrf_token" value="{{csrf}}">
<input type="text" name="task" maxlength="100" placeholder="Enter a task..." required>
<button type="submit">Add</button>
</form>

{% if tasks %}
<ul>
{% for t in tasks %}
<li>
<span>{{t[1]}}</span>
<form method="POST" action="/delete/{{t[0]}}">
<input type="hidden" name="csrf_token" value="{{csrf}}">
<button class="del">Delete</button>
</form>
</li>
{% endfor %}
</ul>
{% else %}
<div class="empty">No tasks yet 🚀</div>
{% endif %}
</div>
</body>
</html>
"""

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
    return g.db

@app.teardown_appcontext
def close(_):
    con = g.pop("db",None)
    if con:
        con.close()

def init():
    db().execute("CREATE TABLE IF NOT EXISTS todos(id INTEGER PRIMARY KEY AUTOINCREMENT, task TEXT NOT NULL)")
    db().commit()

def csrf():
    if "csrf" not in session:
        session["csrf"]=secrets.token_hex(16)
    return session["csrf"]

def verify():
    if request.form.get("csrf_token") != session.get("csrf"):
        abort(403)

@app.after_request
def headers(r):
    r.headers["X-Frame-Options"]="DENY"
    r.headers["X-Content-Type-Options"]="nosniff"
    r.headers["Referrer-Policy"]="no-referrer"
    r.headers["Cache-Control"]="no-store"
    r.headers["Content-Security-Policy"]="default-src 'self'; style-src 'self' 'unsafe-inline';"
    return r

@app.route("/")
def home():
    init()
    rows=db().execute("SELECT id,task FROM todos ORDER BY id DESC").fetchall()
    safe=[(i,escape(t)) for i,t in rows]
    return render_template_string(HTML,tasks=safe,csrf=csrf())

@app.post("/add")
def add():
    verify()
    task=request.form.get("task","").strip()
    if not task or len(task)>100 or any(ord(c)<32 for c in task):
        return redirect("/")
    db().execute("INSERT INTO todos(task) VALUES(?)",(task,))
    db().commit()
    return redirect("/")

@app.post("/delete/<int:task_id>")
def delete(task_id):
    verify()
    db().execute("DELETE FROM todos WHERE id=?",(task_id,))
    db().commit()
    return redirect("/")

if __name__=="__main__":
    app.run(host="127.0.0.1",port=5000,debug=False)
