"""A small inventory service.

Items are kept in SQLite, exported to CSV on request, and compressed on the
way out.
"""
import hashlib
import os
import re
import sqlite3
import subprocess
from dataclasses import dataclass

EXPORT_ROOT = "/var/lib/inventory/exports"

SKU_PATTERN = re.compile(r"\A[A-Za-z0-9-]{1,32}\Z")


@dataclass(frozen=True)
class Item:
    sku: str
    name: str
    quantity: int


def connect(path: str) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


def find_item(connection: sqlite3.Connection, sku: str) -> Item | None:
    """Looks an item up by its stock keeping unit."""
    row = connection.execute(
        "SELECT sku, name, quantity FROM items WHERE sku = ?", (sku,)
    ).fetchone()
    if row is None:
        return None
    return Item(sku=row["sku"], name=row["name"], quantity=row["quantity"])


def find_items(connection: sqlite3.Connection, skus: list[str]) -> list[Item]:
    """Looks several items up at once.

    SQLite has no way to bind a list, so the query is built to carry one
    placeholder per argument.
    """
    if not skus:
        return []
    placeholders = ", ".join("?" for _ in skus)
    query = f"SELECT sku, name, quantity FROM items WHERE sku IN ({placeholders})"
    rows = connection.execute(query, tuple(skus)).fetchall()
    return [
        Item(sku=row["sku"], name=row["name"], quantity=row["quantity"])
        for row in rows
    ]


def adjust_quantity(connection: sqlite3.Connection, sku: str, delta: int) -> int:
    """Adds delta to an item's quantity, refusing to go below zero."""
    item = find_item(connection, sku)
    if item is None:
        raise KeyError(sku)
    updated = item.quantity + delta
    if updated < 0:
        raise ValueError("quantity would go negative")
    connection.execute(
        "UPDATE items SET quantity = ? WHERE sku = ?", (updated, sku)
    )
    connection.commit()
    return updated


def export_path(sku: str) -> str:
    """The file an item's export is written to."""
    if not SKU_PATTERN.fullmatch(sku):
        raise ValueError("not a stock keeping unit")
    return os.path.join(EXPORT_ROOT, f"{sku}.csv")


def compress_export(path: str) -> None:
    """Compresses an export in place."""
    subprocess.run(["gzip", "--force", path], check=True)


def file_digest(path: str) -> str:
    """A digest used to notice that an export changed on disk."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def describe(item: Item) -> str:
    """A line of prose about an item, for the operator log."""
    return f"{item.sku}: {item.name}, {item.quantity} in stock"
