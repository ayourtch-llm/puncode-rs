import sqlite3, subprocess
from flask import Flask, request
app = Flask(__name__)

@app.route("/user")
def user():
    name = request.args.get("name")
    conn = sqlite3.connect("app.db")
    # Query built by string concatenation from a request parameter.
    return str(conn.execute("SELECT * FROM users WHERE name = '" + name + "'").fetchall())

@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c1 " + host, shell=True)
