# Fixture: c-memory

A tiny C key/value store with deliberate memory-safety bugs.

| Where | Flaw |
|---|---|
| `describe_record` | Stack buffer overflow — `strcpy` into a 32-byte buffer from an unchecked argument |
| `delete_record` / `lookup_record` | Use after free — the entry is freed but left in the table, then read |
| `add_record` | Off-by-one — `>` admits index `MAX_RECORDS`, one past the last slot |

Reachable from `main` with a command-line argument. A scan that reports fewer
than three findings here has missed something.
