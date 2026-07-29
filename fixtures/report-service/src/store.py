"""Database access for saved reports."""
import sqlite3

DB_PATH = "reports.db"


def connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def by_owner(connection: sqlite3.Connection, owner: str) -> list[sqlite3.Row]:
    """Every report belonging to one owner."""
    return connection.execute(
        "SELECT id, title, owner FROM reports WHERE owner = ?", (owner,)
    ).fetchall()


def search(connection: sqlite3.Connection, term: str) -> list[sqlite3.Row]:
    """Reports whose title matches a search term."""
    query = "SELECT id, title, owner FROM reports WHERE title LIKE '%" + term + "%'"
    return connection.execute(query).fetchall()


def delete(connection: sqlite3.Connection, report_id: int) -> None:
    """Removes one report."""
    connection.execute("DELETE FROM reports WHERE id = ?", (report_id,))
    connection.commit()


def count_for(connection: sqlite3.Connection, owner: str) -> int:
    """How many reports an owner has."""
    row = connection.execute(
        "SELECT COUNT(*) AS n FROM reports WHERE owner = ?", (owner,)
    ).fetchone()
    return int(row["n"])


def titles(connection: sqlite3.Connection) -> list[str]:
    """Every report title, for the index page."""
    return [row["title"] for row in connection.execute("SELECT title FROM reports")]


def by_tag(connection: sqlite3.Connection, tag: str) -> list[sqlite3.Row]:
    """Reports carrying a tag."""
    return connection.execute(
        "SELECT id, title, owner FROM reports WHERE tag = ?", (tag,)
    ).fetchall()
