# Fixture: flask-injection

A small Flask service with two deliberate vulnerabilities. Used to check that a
scan finds what it should.

| Where | Flaw |
|---|---|
| `src/app.py` `/user` | SQL injection — the query is concatenated from `?name=` |
| `src/app.py` `/ping` | OS command injection — `subprocess` with `shell=True` and `?host=` |

Both are reachable from unauthenticated HTTP requests. A scan that reports fewer
than two findings here has missed something.
