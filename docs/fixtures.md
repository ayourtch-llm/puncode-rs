# Fixtures

Small projects with deliberate flaws, used to check that a scan finds what it
should.

**These notes live outside the fixture directories on purpose.** A scan reads
everything in its target, so a README listing the planted flaws would be handing
over the answers — the run would be measuring reading comprehension rather than
detection.

**The rule covers comments, and that is easy to forget.** It was forgotten here
for longer than the README was: `c-memory` named all three of its flaws in
comments (`/* Use after free: ... */`) and `clean-python`'s docstrings explained
why each decoy was safe. Both were fixed on 2026-07-29, and every measurement
before that date was taken with the answers in the source.

When adding to a fixture, write the comments the way you would in code meant to
work: what the routine is for, not what is wrong with it. If a comment would
help a reviewer find the bug, it will help the scanner too, and then the number
means nothing. The tell is easy to check — the one fixture here that always had
ordinary comments, `node-traversal`, is the only one that has ever failed to
find something.

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

Each fixture is copied to a scratch git repository and scanned there, because
the fixtures live inside this checkout and a commit during a run moves HEAD,
which the workbench refuses at the very end — after all the work is done.

One consequence, deliberate: every run creates a fresh scratch repository, so
runs of the same fixture have different target identities and the workbench
cannot relate them. `scans compare` and `scans match` therefore do not work
across corpus runs. `bench` and `consensus` are unaffected — they match on file
and line rather than on target identity, which was checked across two runs with
different target IDs — and they are what the corpus is compared with. Scanning a
real repository is unchanged: the same repository keeps the same identity across
runs.
