# Handoff

Working notes for whoever picks this up. The commits say what changed; this says
what was learned, what nearly went wrong, and what is still open. Read
[README.md](README.md) first for what the tool is.

## State

A complete Rust port of `@openai/codex-security`, library-first with a thin CLI.
994 tests, clippy clean, rustfmt clean, `unsafe_code` forbidden. The TypeScript
package in `tmp/` was used as a live oracle throughout; differential tests hold
prompt construction, config hardening, currency formatting, CSV parsing,
terminal rendering and document extraction byte-identical to it.

Verified end to end against a local 35B model: full scan, both fixtures, real
findings, exit 0.

## The naming split — read before any rename

Two kinds of "codex" live in this tree and only one is ours.

**Never rename** — these are how the tool talks to somebody else's software:

- `CODEX_SECURITY_*` environment variables the plugin reads
- `CODEX_HOME`, `codex exec`, the `codex` binary
- `codex-security-plugin` — the `scan.producer.name` the workbench requires
- `codex-security` and `codex-security-sdk` — plugin and marketplace names
- `$codex-security:validation`, `$codex-security:fix-finding` — skill ids
- `codex_security_scan` — a permission profile codex loads from config
- `codex-security/v1`, `codex-security-snapshot/v1` — algorithm labels embedded
  in finding fingerprints and snapshot digests
- `~/.codex/state/plugins/codex-security` and the plugin cache paths
- `codex-security.findings`, `.scan-manifest`, `.coverage` — documentType values
- `github.com/openai/codex-security` — a real address
- prompt text sent to the agent, which is contract, not branding

A blanket rename compiled fine and then failed on fingerprint identity, plugin
discovery, config hardening and the prompt oracle. Renaming the fingerprint
labels would have **silently changed the identity of every finding**. The tests
caught all nine; a search for "our name" would not have distinguished them.

## Environment: why scans need `--yolo` here

This host is an unprivileged **Incus/LXC container with an idmapped root
filesystem**. Bubblewrap cannot start: a user namespace with an *identity* uid
map — which is what bwrap creates — may not change mount propagation on such a
root. A *root* map can.

```
unshare --user --map-current-user --mount   → fails    (what bwrap does)
unshare --user --map-root-user    --mount   → succeeds
```

Fails identically under sudo and inside a prepared namespace. `/proc/1/cgroup`
does **not** reveal Incus — check `/dev/incus` and `systemd-detect-virt`.

Real fix is host-side (`security.nesting`, no idmapped rootfs, or a dedicated
container). Until then `--dangerously-disable-sandbox` (`--yolo`). Note
`sandbox_mode` is deliberately stripped from config by
`api/config_projection.rs`, so `--codex sandbox_mode=…` is silently dropped —
that is correct and should stay.

## Local model recipe

```sh
puncode-security scan <repo> \
  --base-url http://<host>/v1 --endpoint-compat merge-system \
  --dangerously-disable-sandbox --model <model> --output-dir <dir-outside-repo>
```

Each flag answers a distinct blocker; drop one and it fails somewhere else.

## Three wrong diagnoses I committed to, and what was actually true

Recorded because each was confidently reasoned and wrong, and the correction
came only from capturing reality.

**1. "errno 5005 means a seccomp filter."** It does not. 5005 is a *libmount*
code (`MNT_ERR_NOFSTAB`) — `mount(8)` falls back to an fstab lookup after the
syscall fails and reports that instead. I built a whole seccomp theory on a
misread string. Every syscall bwrap needs actually reaches the kernel.

**2. "The template rejects codex's message ordering."** It does not. Capturing
the request through a logging proxy showed `instructions` plus `developer`
items — system content already first. The template permits exactly **one**
system message and llama.cpp makes one per item. The provider's own error text
(`System message must be at the beginning`) points at ordering and sends you
down a dead end. `diagnosis.rs` says so explicitly for this reason.

**3. "The model is unreliable."** It is not. Across seven runs it found every
planted vulnerability, every time. All failures were bookkeeping it had no way
to know — nothing told it what scope the workbench had registered, and no
shipped skill mentions the workbench contract at all. Fixed by *stating* what
the port knows (scope) and telling the agent to *ask* for what it cannot compute
(target kind, via `workbench_db.py get-scan` → `contract.target.allowedKinds`).

The pattern worth keeping: **state what you know, ask for what you cannot
compute.** Target kind depends on a registration snapshot compared against the
working tree now; computing it here would mean reimplementing the plugin's
digest logic, which would drift.

## Workbench constraints that look like bugs

- **One scan per output directory.** A second scan into the same one fails on
  `UNIQUE constraint failed: scans.scan_dir`, reported as a raw sqlite
  traceback. The plugin *also* requires the directory to be empty, so `rm -rf`
  and `--archive-existing` both satisfy that check and then fail on the record,
  which outlives the files. Only a new `--output-dir` works. Now diagnosed.
- **Output may not live inside the scanned repository.** Fixtures live in this
  checkout, so the checkout is the protected root and results must go elsewhere.

## Extending the prompt

`api/prompt.rs` carries two deliberate additions upstream does not have (scope,
and the contract read). The differential test in `tests/prompt.rs` strips
exactly those lines via `is_scope_extension` and compares the rest, so unrelated
drift still fails. **If you add another prompt line, add it there too** —
otherwise the oracle test fails and the temptation is to weaken it.

## Fixtures

`fixtures/` holds two projects with planted flaws. What is planted is documented
in `docs/fixtures.md`, **outside the fixture directories on purpose** — a scan
reads its whole target, so a README listing the answers turns the exercise into
reading comprehension. It passed 2/2 and 3/3 that way before anyone noticed, and
that result was discarded.

`./scripts/scan-fixtures.sh` runs both and fails if either comes up short.

## The unpacked plugin is verified, and why

The plugin is embedded in the binary but unpacked to
`~/.codex-security/bundled/plugin-<version>/` and reused between commands. The
original design trusted a marker file, so only `plugin.json` was re-read; the
other 100-odd files, including the Python a scan executes, were never checked
again. Appending a line to `scripts/workbench_db.py` in that tree left
everything running normally and `doctor` reporting the plugin "ok" —
demonstrated, not theorised.

The marker now holds a digest over sorted path plus contents, verified before
reuse, and a mismatch replaces the tree and says so. Do not "optimise" that
check away: it costs a fraction of the ~300 ms a `doctor` run already takes,
before a scan that runs for minutes.

## Endpoint credentials are a type, not a discipline

An endpoint URL can carry a username and password. It leaked three times — into
`provenance.json`, then into `doctor` and both dry-run renderings — and each fix
was a call to a redaction function at the site that printed it. Each time a site
was missed, because nothing at the call site said which uses were safe.

`provenance::Endpoint` now holds it. `Display` **and** `Debug` are redacted; the
credential-carrying form is reachable only through `for_request()`. Printing one
the obvious way is safe, and the unsafe path is named so it is visible when
reading and greppable when auditing.

`Debug` matters as much as `Display` here: it reaches people through panics,
logs, and any derived `Debug` on a struct that holds one — `ScanArgs` derives it.
A test asserts both.

**If you add a field carrying something sensitive, give it a type rather than a
convention.** Three fixes over two days did not stop the leak; the type did.

## The seal cannot check itself

The manifest carries a digest for every artifact a scan produced and
`contract::seal` verifies each one. **The manifest is not an artifact of
itself**, so nothing in the contract checks it — replace it and every digest it
records still matches. A real scan directory verified as fully consistent while
the workbench had refused to publish it.

`manifest_form.rs` checks the root of the chain, using two properties of the
plugin's single document writer:

```python
json.dumps(payload, indent=2, sort_keys=True) + "\n"
os.open(..., O_CREAT | O_EXCL, 0o600)
```

Sorted keys and mode 600. They share no implementation, and across 25 real
manifests on this machine they agreed on every one — which is what a genuine
common cause looks like rather than a coincidence.

**Do not reconstruct the canonical bytes and compare.** That was the obvious
approach: Python escapes non-ASCII by default and Rust does not, so a manifest
naming a path with an accent in it would be called a forgery. The check reads
structure instead.

**And the mistake worth remembering.** The first version said a document in this
state meant the workbench had refused the scan. It sounded right, the c-memory
case fit it exactly, and it was wrong: of eleven flagged scans, three had
published normally. It now reports the fact and not a verdict and deliberately
does **not** fail verification. If you are tempted to make it fail, get evidence
first — a check that cries wolf gets switched off, and then it protects nothing.

## Where the bugs have actually been

Not in units. Every unit test passed while each of these was live. They were
found by two questions, both worth asking again:

**"Which of these features have never met each other?"**

- `--repeat` with `--capture-traffic`: every run opened the same file with
  truncate, so run two erased run one. Each feature was correct alone.
- A credential redaction applied to `provenance.json` and to none of the three
  other places that printed the same URL.

**"What checks the checker?"**

- `verify` reported "documents agree with each other and with their digests" for
  a scan the workbench had refused, because the manifest verifies everything
  except itself. Every check in the chain passed; the chain had no root.

**"Which branch has never actually run?"**

- `verify` reading a provenance record: it reported "no provenance record" while
  the file sat in the directory, because the read side lacked `serde(default)`
  and every record a real scan writes omits some optional field. The round-trip
  test passed throughout — it used a record with every field populated, which is
  the case that never happens.

The pattern in all of them: a test that examined the easy case, and looked like
coverage. When you add something, run the path a user will actually hit, with
the inputs they will actually have, and read the output rather than the exit
code.

Branches verified this way and known good: capture truncation reports the real
size, `--min-agreement` announces how many it hid, `--repeat` names which runs
failed, provenance is written per run under `--repeat`.

## Running the corpus

`./scripts/scan-fixtures.sh --local <url> --model <model> -- --dangerously-disable-sandbox`,
then `puncode-security bench <results>`.

Each fixture is copied to a scratch git repository and scanned there, not in
this checkout. The fixtures live inside this repo, so a commit during a run
moves HEAD and every scan is refused at the very end with "Repository HEAD
changed while the scan was running" — after doing all the work. That cost a
complete corpus run once. Do not undo the copy.

Measured results, one model (deepreinforce-ai_Ornith-1.0-35B, local):

| Run | Detection | False positives | Decoy trips |
|---|---|---|---|
| 12:59 | 7 of 8 | 0 | — (no decoys yet) |
| 14:53 | 8 of 8 | 0 | 0 of 5 |
| 15:09 | 7 of 8 | 0 | 0 of 5 |

Three runs over an unchanged corpus. **Seven of the eight flaws are found every
time; CWE-208, the timing-unsafe comparison, is found roughly one run in three.**
Read a single run accordingly — 88% and 100% here are the same model on the same
code, and the difference is entirely that one flaw.

And the two 88% runs are not the same result either. Reading the scans rather
than the scores showed CWE-208 came out **never noticed** in the 12:59 run and
**seen and deferred, with a written reason**, in the 15:09 one:

> Token is sourced from environment variable, not hardcoded. The CWE-259 framing
> is weakened. Exploitation requires token leakage or a timing side-channel,
> neither guaranteed. Deferred pending deployment-context review.

That is a defensible argument about severity, not a miss — and the benchmark had
been calling it a miss because it only ever read `findings.json`. `bench` now
also reads `coverage.json` and reports the two apart. Deferrals do **not** count
toward detection; a scanner that explained every flaw away must still score
zero.

Worth remembering as a habit rather than a fix: **the scan wrote down more than
the score was reading.** `coverage.json` carries surfaces, dispositions, open
questions and deferrals, and none of it was scored. When a measurement looks
unstable, check whether the instrument is reading everything the subject said.

The decoys have never been tripped, across both runs that had them.

Severity is where the model differs most, and consistently: it rates the
memory-safety flaws lower than this corpus does and injection higher, and it
disagrees with *itself* between runs — `use-after-free` came out medium in one
run and high in another, `sqli-user` critical then high. `bench --baseline`
names that; the aggregate rate hides it entirely.

Two save failures seen that are not detection problems: "The sealed scan
manifest changed while it was being read" and, before the snapshot fix,
"Repository HEAD changed while the scan was running". Both happen after all the
work is done.

## Open

1. **`node-traversal` and `c-memory` exit 2 for reasons that are not detection
   failures.** `node-traversal` completes fully and exits 2 because coverage is
   `partial` — it found and reported everything it meant to. `c-memory` fails at
   the very end with "The sealed scan manifest changed while it was being
   published", after all the work is done. Neither is a missed flaw, and reading
   the exit code alone would suggest otherwise.
2. **`report.md` finalisation is flaky.** Detection is reliable; the agent
   sometimes stops before running `finalize_scan_contract.py`, leaving an
   otherwise-good scan at exit 2. Last gap between "finds the bugs" and "clean
   exit 0". Likely the same class as the scope/contract fixes.
3. **No control run against a stronger model.** Everything concluded about model
   behaviour comes from one local model over ~10 runs. A hosted run would
   separate general behaviour from this model's habits.
4. **`--exclude` does not exist.** If it is ever added, registration must carry
   it and the hard-coded `excludePaths: []` in `prompt.rs` becomes wrong.
5. **Upstream feedback.** No shipped skill mentions the workbench contract, and
   `includePaths`/`excludePaths` have no schema description. That is why a
   weaker model never finds the rule. Worth reporting upstream.

## The ETXTBSY flake, and the rule for new suites

Tests that write an executable stub and spawn it race on Linux. The suite runs
in parallel threads; a thread that forks between another thread's open and close
inherits the write descriptor, and the exec of that file fails with **`Text file
busy`** until the child reaches its own exec. It is rare — one occurrence across
roughly thirty full-workspace runs — and it is not a real defect in the code
under test.

Three sites carry the remedy now: `auth.rs`, `api/client.rs`, and
`tests/scan.rs`. **If you add a suite that writes a stub and spawns it, add the
retry.** These files write `0o755` stubs and do not have it yet, so they are the
ones to watch:

`runtime/marketplace.rs`, `runtime/python.rs`, `runtime/isolated.rs`,
`runtime/output.rs`, `runtime/workbench.rs`, `tests/trusted_executable.rs`,
`tests/codex.rs`, `tests/multiscan.rs`, `tests/scan_comparison.rs`,
`cli/tests/scan_run.rs`.

They were left alone deliberately: none has been observed to flake, and patching
ten files against a race that may never fire in them is ten unevaluated changes.

**Do not verify this fix by rerunning until it passes.** At a one-in-thirty base
rate that proves nothing, and twelve clean runs after the fix proved nothing
either. `retries_a_stub_that_is_still_being_written` creates the condition
deliberately by holding a write descriptor open, asserts the operating system
really does refuse the exec before relying on it, and then releases it from
another thread. Removing the retry makes that test fail — checked, not assumed.

A flaky suite is worse than a smaller one: it teaches whoever runs it to rerun
rather than read, and then a real failure gets rerun too.

## Process notes that cost real time

- **One run proves nothing here.** Model output varied on every attempt. Two
  separate "green" results turned out to measure nothing — a prompt audit whose
  regex matched no lines, and the fixture run with the answers included. Check
  what a passing test actually examined.
- **Verify the instrument before the measurement.** A silent 20 000-char
  truncation in the capture harness corrupted its JSON and cost three runs. Any
  truncation must announce itself; `endpoint_shim.rs` records `truncated` and
  the real length for exactly this reason.
- **Editing a running Python process changes nothing.** A stale proxy served
  three runs with old code after I had "fixed" it. Kill and prove the new code
  is live.
- **`pkill -f <pattern>` matches your own shell** if the pattern appears in its
  command line. It killed a scan I had just started.
- **Match error patterns against captured output, never invented strings.** The
  unreachable-endpoint recogniser was written against "connection refused" and
  never fired; codex actually says `error sending request for url`.
- **Dead-code warnings found three real gaps** — a rerun ignoring saved config,
  a dropped account fallback, and a redundant accessor. Do not silence them.
- **`cargo fmt` reflows call sites**, so scripted replacements written against
  unformatted code silently miss. Re-check after formatting, and format before
  committing (one commit here needed a follow-up for exactly that).
