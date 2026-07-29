# Fixtures

Small projects with deliberate flaws, used to check that a scan finds what it
should.

**These notes live outside the fixture directories on purpose.** A scan reads
everything in its target, so a README listing the planted flaws would be handing
over the answers — the run would be measuring reading comprehension rather than
detection.

## flask-injection

A Flask service, reachable unauthenticated.

| Where | Flaw |
|---|---|
| `src/app.py` `/user` | SQL injection — the query is concatenated from `?name=` |
| `src/app.py` `/ping` | OS command injection — `subprocess` with `shell=True` and `?host=` |

Expected: **2 findings**.

## c-memory

A C key/value store.

| Where | Flaw |
|---|---|
| `describe_record` | Stack buffer overflow — `strcpy` into a 32-byte buffer from an unchecked argument |
| `delete_record` / `lookup_record` | Use after free — the entry is freed but left in the table, then read |
| `add_record` | Off-by-one — `>` admits index `MAX_RECORDS`, one past the last slot |

Expected: **3 findings**.

Verified to misbehave rather than merely look wrong: a long argument trips stack
smashing detection, and the freed entry is read by a later lookup.

## node-traversal

A small Express file server and link previewer.

| Where | Flaw |
|---|---|
| `/file` | Path traversal — `path.join` with an unvalidated `?name=` |
| `/preview` | SSRF — server-side fetch of an arbitrary `?url=` |
| `/admin` | Timing-unsafe token comparison |

Expected: **3 findings**.

## clean-python

An inventory service with **nothing planted**, and five **decoys** — routines
written to resemble things that are usually unsafe while being safe:

| Where | Looks like | Safe because |
|---|---|---|
| `find_items` | SQL injection | the f-string interpolates placeholders derived from the *count* of arguments, never their contents; values are still bound |
| `export_path` | path traversal | the argument is checked against `\A[A-Za-z0-9-]{1,32}\Z` first, so it cannot hold a separator or `..` |
| `compress_export` | command injection | arguments are a list, program name a literal, no shell involved |
| `file_digest` | weak password hashing | SHA-256 for file integrity; there is no password in this service |
| `describe` | injection via interpolation | the string is only ever printed |

An empty control asks only whether a scanner invents findings from nothing,
which is the easy case. Decoys ask whether it is fooled by plausible code —
where trust is actually lost, because the reviewer has to read the finding to
discover it is wrong.

The two that could plausibly have been wrong were verified by running attacks
against them, not by reading: injection payloads through `find_items` matched
nothing and left the table intact, and every traversal payload to `export_path`
was refused.

Expected: **0 findings**. A finding here is reported as a decoy trip, naming
what fooled it.

## Running them

```sh
./scripts/scan-fixtures.sh                                     # hosted Codex
./scripts/scan-fixtures.sh --local http://host:8080/v1 --model my-model
```

The expected counts are held in the script, not in the fixtures.
