"""HTTP routes for the report service."""
from flask import Flask, request, session

from . import store, util

app = Flask(__name__)


def require_admin() -> None:
    if not session.get("is_admin"):
        raise PermissionError("admin only")


@app.route("/reports")
def reports():
    connection = store.connect()
    owner = session.get("user", "")
    return str(store.by_owner(connection, owner))


@app.route("/reports/search")
def search():
    connection = store.connect()
    term = util.normalise_term(request.args.get("q", ""))
    return str(store.search(connection, term))


@app.route("/reports/tagged")
def tagged():
    connection = store.connect()
    tag = util.known_tag(request.args.get("tag", ""))
    return str(store.by_tag(connection, tag))


@app.route("/admin/reports")
def admin_reports():
    require_admin()
    connection = store.connect()
    return str(store.by_owner(connection, request.args.get("owner", "")))


@app.route("/admin/purge")
def admin_purge():
    require_admin()
    connection = store.connect()
    store.delete(connection, int(request.args.get("id", "0")))
    return "purged"


@app.route("/admin/export")
def admin_export():
    connection = store.connect()
    return str(store.by_owner(connection, request.args.get("owner", "")))
