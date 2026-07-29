"""A small inventory service.

Written to be unremarkable: parameterised queries, no shell, no user-controlled
paths. Nothing here is meant to be found.
"""
import sqlite3
from dataclasses import dataclass


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
