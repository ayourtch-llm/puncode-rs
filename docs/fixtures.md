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

An inventory service with **nothing planted**: parameterised queries, no shell,
no user-controlled paths. Anything reported here is a false positive. This
fixture exists because recall alone says nothing about whether a scanner is
worth running.

Expected: **0 findings**.

## Running them

```sh
./scripts/scan-fixtures.sh                                     # hosted Codex
./scripts/scan-fixtures.sh --local http://host:8080/v1 --model my-model
```

The expected counts are held in the script, not in the fixtures.
