# puncode-security

A Rust port of [`@openai/codex-security`](https://github.com/openai/codex-security),
OpenAI's agentic security scanner. It drives the `codex` binary against a
repository, following the bundled plugin's review workflow, and produces a
validated set of findings.

Built as a library with the command line as a thin cover over it, so the scan
can be embedded as easily as it can be run.

Beyond parity with upstream, this port can point the whole thing at **any
OpenAI-compatible endpoint**, including a model on your own hardware. That is
the part most likely to be why you are here, so it has [its own section](#running-against-a-local-model).

## What this actually is

`codex` is used as an **agent**, not as a way to call a model. The scan hands it
a task — *follow this skill, review this repository, write these artifacts* —
and the agent then runs shell commands, reads source, and invokes the plugin's
Python helpers. The security knowledge lives in the plugin's skills; the model
decides what to run.

That matters for two reasons: the agent needs a working sandbox to execute
anything, and a weaker model can review code competently while still getting the
bookkeeping wrong.

## Build

```sh
cargo build --release -p puncode-security-cli
```

Requires the `codex` CLI on `PATH`. The security plugin is vendored in-tree, so
there is nothing else to install.

## Use

```sh
puncode-security scan .                       # scan a repository
puncode-security scan . --dry-run --json      # report what would run, spend nothing
puncode-security scans list                   # past scans
puncode-security export <scan-dir> --export-format sarif
puncode-security info                         # versions and configuration
```

Exit codes: `0` clean, `1` findings at or above `--fail-on-severity`, `2` error.

## Running against a local model

Point it at any OpenAI-compatible endpoint:

```sh
puncode-security scan . \
  --base-url http://your-host:8080/v1 \
  --endpoint-compat merge-system \
  --model /path/or/name/of/the/model
```

The endpoint address is never hardcoded anywhere; it is a parameter, and
`CODEX_SECURITY_BASE_URL` works too. The API key is read from the variable named
by `--api-key-env` (default `OPENAI_API_KEY`) — the config records the *name* of
that variable, never the key.

### Why `--endpoint-compat merge-system`

Codex sends `instructions` plus several `developer` items. Servers such as
llama.cpp turn each of those into a separate system message, and many chat
templates accept exactly one. The result is a refusal reading
`System message must be at the beginning`, which is misleading — the ordering is
already correct, there are simply too many. This flag folds them into one,
preserving order and content, via a forwarder that runs on loopback for the
duration of the scan.

### If the sandbox cannot start

Codex sandboxes the agent's shell commands with bubblewrap. Where that cannot
run — an unprivileged container with an idmapped root filesystem is the common
case — every command fails and the scan ends having produced nothing.

Prefer a host where the sandbox works, or a container dedicated to the scan. If
the host is already confined *and* the repository is trusted:

```sh
puncode-security scan . --dangerously-disable-sandbox   # alias: --yolo
```

That runs the agent's commands with your access to the machine, over a
repository you are scanning precisely because you do not trust it. The container
becomes the only boundary. Do not reach for it by default.

### Diagnosing an endpoint

```sh
puncode-security scan . --base-url ... --capture-traffic ./traffic.jsonl
```

Records what was sent and what came back. The file holds prompts, model output
and source excerpts from the repository, so it is written `0600`, refused inside
the repository being scanned, and never created unless asked for.
`--capture-max-bytes` raises the per-body cap (`0` removes it); a body that was
cut short always says so.

### Cost

A cost ceiling is refused against a custom endpoint. Model pricing describes the
hosted service, not yours, and a ceiling that cannot be enforced is worse than
none because it is believed to be protecting you.

## Fixtures

Two small projects with deliberate, documented flaws:

| Fixture | Language | Planted flaws |
|---|---|---|
| `fixtures/flask-injection` | Python | SQL injection, OS command injection |
| `fixtures/c-memory` | C | Stack buffer overflow, use after free, off-by-one |

What is planted in each is documented in [docs/fixtures.md](docs/fixtures.md) —
deliberately *outside* the fixture directories, since a scan reads everything in
its target and a list of the answers would make the exercise meaningless.

Run a scan against both and compare against the expected counts:

```sh
./scripts/scan-fixtures.sh                                     # hosted Codex
./scripts/scan-fixtures.sh --local http://host:8080/v1 --model my-model
```

It exits non-zero if any fixture reports fewer findings than are planted, so a
scan that quietly stops working is visible.

### Scanning the same target twice

The workbench records one scan per output directory, so a second scan needs a
different `--output-dir`. Emptying the old one is not enough — the record
outlives the files, and `--archive-existing` does not help either. The fixture
runner stamps its output directory per run for this reason.

## Naming

The crates, the binary and this project are named `puncode-security`. Names
belonging to OpenAI's tooling are kept exactly as they are, because they are how
this interoperates rather than branding — the `CODEX_SECURITY_*` environment
variables the plugin reads, `CODEX_HOME`, the `codex` binary, the
`codex-security` plugin and `codex-security-sdk` marketplace, and the
`codex-security/v1` algorithm labels embedded in finding fingerprints. Renaming
those would not remove a trademark reference; it would break interoperation, and
in the fingerprint case would silently change the identity of every finding.

## Relationship to the original

This is an independent Rust reimplementation of `@openai/codex-security`.
Behaviour follows upstream closely enough that the TypeScript package was used
as a live oracle while porting: where its behaviour was not obvious from the
source it was probed, and the answers committed as fixtures. Differential tests
cover currency formatting, CSV parsing, terminal rendering, prompt construction,
config hardening and document text extraction.

The API shape is Rust rather than a transliteration — `Result` and a typed error
enum, builders instead of option bags, an observer trait instead of a set of
callbacks.

The security plugin under `crates/puncode-security/plugin/` is redistributed
**verbatim and unmodified** from the upstream project. See [NOTICE](NOTICE).

## Licence

Apache-2.0, the same as the original project. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).
