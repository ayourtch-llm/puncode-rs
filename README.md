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

### Exit codes

| Code | When |
|---|---|
| `0` | the scan completed and nothing met `--fail-on-severity` |
| `1` | a finding at or above `--fail-on-severity` |
| `2` | the scan failed, **or** completed without covering everything it was asked to |

Two of these surprise people in CI, so they are worth saying plainly.

**Findings alone do not fail a run.** Without `--fail-on-severity` a scan that
reports critical findings still exits `0`. That matches upstream, and it means a
CI job which only checks the exit code will pass while findings pile up. Set the
threshold you actually want to block on.

**Incomplete coverage exits `2`, not `0`.** A scan that ran cleanly but could not
review everything in scope has not answered the question it was asked, and
reporting that as success would let a job go green on a partial review.

## Before you spend a scan

```sh
puncode-security doctor --base-url http://your-host:8080/v1 --model my-model
```

```
  ok       codex            codex-cli 0.146.0
  ok       plugin           unpacked at ~/.codex-security/bundled/plugin-0.1.14
  ok       python           /usr/bin/python3.12
  BROKEN   sandbox          bwrap: Failed to make / slave: Permission denied
                            Commands could not run: the Codex sandbox could not
                            start... an unprivileged container with an idmapped
                            root filesystem is a common cause.
  ok       endpoint         answers at http://your-host:8080/v1
  BROKEN   system messages  the endpoint refused two system messages
                            ...The order is not the problem, so reordering will
                            not help. Retry with --endpoint-compat merge-system.

2 thing(s) would stop a scan
```

Real output. A scan against a local model can run for ten minutes and end in
"completed without required artifacts" when the actual answer was available in a
second. Every check here exists because something went wrong once and took a
long time to explain.

Two rules it holds to. **Checks are run, never inferred from configuration** —
that a sandbox mode is set says nothing about whether a namespace can be created
on this host, and only trying it answers that. **A check that could not run is
reported as skipped, never as working**, and does not affect the exit code;
treating unknown as broken teaches people to ignore the tool.

Exits 1 if anything would stop a scan, so it can gate a job. `--json` for the
same in machine-readable form.

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

The forwarder is on loopback, which keeps other machines out but not other
processes on this one, so each run's URL carries a secret first path segment.
Without it a request is refused before anything is forwarded or recorded — a
scan's forwarder is otherwise an unauthenticated relay to your endpoint for as
long as it runs.

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
the repository being scanned, refused if the destination is a symbolic link, and
never created unless asked for. A destination that already exists is tightened to
`0600` rather than trusted to be private already.
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

## Measuring whether it works

A scan produces findings. Whether they are the *right* ones is a separate
question, and one nobody running a scanner can usually answer.

`benchmark/ground-truth.json` records every flaw planted in the corpus — file,
line range, CWE, severity — and `bench` scores a set of scans against it:

```sh
./scripts/scan-fixtures.sh --local http://host:8080/v1 --model my-model
puncode-security bench /tmp/puncode-fixture-scans/<run>
```

```
Detection

  flask-injection      2 of 2 found
  c-memory             3 of 3 found
  node-traversal       2 of 3 found
                       set aside, not reported: timing-unsafe-compare
                         "Token is sourced from environment variable, not hardcoded. The CWE-259…"
  clean-python         control — 0 false positive(s)

  detection      88%  (7 of 8)
  unmatched      0  (0 on fixtures with nothing planted)
  not reported   0 never noticed, 1 seen and set aside

By class

  CWE-22           1 of 1      CWE-121          1 of 1
  CWE-78           1 of 1      CWE-193          1 of 1
  CWE-89           1 of 1      CWE-208          0 of 1
  CWE-918          1 of 1      CWE-416          1 of 1
```

Real output, from a 35B model running locally. It found injection, command
injection, traversal, SSRF, a stack overflow, a use-after-free and an off-by-one.
Nothing was reported against the clean fixture.

### Not found is two different things

The last line above is the one worth reading twice. The timing-unsafe comparison
was not reported — but the scan had seen it, and written down why it was leaving
it alone. That is not the same as missing it, and a report that says only "2 of
3" cannot tell you which happened.

Both states are real here. Over three runs of the same model against the same
unchanged corpus, that one flaw came out **never noticed** once, **reported**
once, and **seen and set aside with reasoning** once. The first two runs both
scored 88%, and they were not the same result.

The difference decides what you do next:

- **Never noticed** is a blind spot. The scanner did not look, or looked and saw
  nothing. That needs a better scanner, a better prompt, or a different model —
  and nothing you say to this one will help.
- **Seen and set aside** is a judgement, written down, that you can read and
  disagree with. Here it was *"Token is sourced from environment variable, not
  hardcoded"* — a defensible argument about severity that still leaves a timing
  side channel in the code. That needs a person, not a better model.

So `bench` reads the scan's `coverage.json` alongside its findings and reports
the two separately. **A deferral never counts as a detection**: the rate is the
share that was actually reported, and a scanner that explained every flaw away
would still score zero. It also names deferrals it cannot place rather than
dropping them, because scoring that silently discards what it cannot account for
looks more complete than it is.

On a control fixture the same signal runs the other way — a deferral landing on
one of the decoys is reported as *nearly fooled, then stopped short*, which is
the best outcome available there and is invisible unless something says it.

It also compares severities:

```
  severity       4 of 8 rated as the corpus does
                 cmdi-ping: corpus critical, scan high
                 use-after-free: corpus high, scan medium
```

Real output from the run that scored 100% detection. Finding everything says
nothing about whether it was rated sensibly, and a critical rated medium is
nearly as bad as one missed — a reviewer working down a list by severity gets to
it last, or not at all. On that run the model consistently rated memory-safety
flaws lower than the corpus does.

This is reported as **agreement, not accuracy**. Severity is a judgement and the
corpus is one opinion; the useful signal is where the two differ and in which
direction, not who is right.

Three deliberate choices:

- **Matching is by location, never by wording.** A model saying "OS command
  injection" and one saying "unsafe subprocess invocation" have found the same
  flaw; scoring on titles would measure vocabulary.
- **The corpus contains a fixture with nothing planted in it.** Anything
  reported there is a false positive, and that number decides whether anyone
  keeps the tool switched on — a scanner that cries wolf gets ignored, and then
  it finds nothing at all.
- **A rate over nothing is reported as unmeasured, not as zero.** They are
  different facts, and zero reads as total failure.
- **A flaw the scan argued about is not a flaw it missed.** Reported apart, and
  never counted as found.

### Comparing against an earlier run

```sh
puncode-security bench <results> --baseline <earlier-results>
```

```
Against the baseline

  LOST     timing-unsafe-compare was found before and is not found now
  moved    use-after-free: medium then, high now

One run is weak evidence: this model's output varies between runs over unchanged
code. Repeat before concluding something broke.
```

Real output from two runs of this corpus. A floor tells you the rate moved; this
tells you *what* moved, which is the question worth asking over time. Exits 1
when something that used to be found is no longer found.

Flaws only one run could have found — because the corpus grew or shrank — are
reported as not compared rather than counted either way. And a red result says
plainly that one run is weak evidence, because this model's output varies over
unchanged code and a regression seen once may be nothing.

### Using it as a gate

```sh
puncode-security bench <results> --min-detection 0.8 --max-false-positives 0
```

Exits 1 when a run falls short, so a corpus can guard against a change that
quietly makes detection worse. `--json` gives the same numbers, including which
flaws were missed, for a CI job to consume.

A floor set against a corpus that plants nothing is **refused, not passed**. A
threshold that succeeds without measuring anything reports as a guard while
guarding nothing, which is worse than having no threshold at all.

One finding can claim only one flaw and one flaw only one finding, so neither a
single vague report nor ten copies of the same one can inflate the score.

### The corpus audits itself

Ground truth lives outside the fixtures, always: with the answers inside, an
early run scored 2/2 and 3/3 and measured nothing at all. That was caught by a
person reading the directory listing.

The second time it was not. The rule covers comments, and `c-memory` named all
three of its flaws in them while `clean-python`'s docstrings explained why each
decoy was safe. It survived for days, and every number taken in that period was
measuring reading rather than detection.

Both times the corpus was checked by reading it, and both times reading it is
what failed. So `bench` now reads it instead, on every run, and says so **above**
the numbers rather than below them:

```
THE CORPUS GIVES ITS ANSWERS AWAY

  c-memory/src/store.c:27 says "use after free" — /* Use after free: the record is …
  clean-python/src/inventory.py:48 says "sql injection" — The query is built with an …

A scan reads its whole target, so these numbers measure reading and not
detection. Take the text out and run it again.
```

It looks for phrases that appear in writing *about* code rather than in code
written to work — weakness class names, cited CWE identifiers, and notes
claiming something is deliberate or safe. **It errs toward flagging**, which is
the opposite of the choice made for [scan verification](#the-one-document-the-seal-cannot-check):
that one speaks about somebody's real results, where crying wolf gets it
switched off, while this one speaks about a test corpus its author reads. A
false flag there costs one glance; a miss costs every number the corpus produces.

The audit is checked against the corpus as it actually was before the fix — it
finds all ten leaks — and against the corpus as it is now, on every test run.

## Checking results you were handed

```sh
puncode-security verify <scan-dir>
```

```
  ok       documents agree with each other and with their digests
  ok       2 finding(s), each matching its fingerprint
  produced by  puncode-security 0.1.0, model …, endpoint …, SANDBOX DISABLED

These results are internally consistent.
The seals are digests, not signatures. They catch a document changed without
resealing it; they cannot detect someone who changed it and resealed. And
consistency is not correctness: nothing here says the findings are right.
```

Scan results get passed around — attached to a ticket, copied into a report,
handed to someone who was not there when they were made. This answers the two
questions the files do not: are they internally consistent, and what produced
them. Nothing is re-run and nothing is contacted.

Editing a finding is caught, including an edit that keeps the schema valid — the
sealed digests do not match any more. What it cannot catch is somebody who
changed a document *and* resealed it, which the output says rather than leaving
you to assume otherwise.

It also compares the plugin that produced the scan against the one installed
here. A difference is not a failure — an older scan is still a valid scan — but
it means rerunning here would not be rerunning what made these results, and
that is worth knowing before trying to reproduce them.

### The one document the seal cannot check

The manifest lists a digest for every artifact a scan produced, and each is
verified against what is on disk. That leaves exactly one file unchecked, and it
is the one everything else hangs from: **the manifest is not an artifact of
itself.** Replace it and every digest it records still matches, so the scan
verifies as fully consistent. A real scan directory here did exactly that.

So `verify` looks at the manifest itself. The plugin writes every contract
document through one function, which is specific in two unrelated ways — sorted
keys with a trailing newline, and mode `600` rather than the umask. A document
missing either was written by something else:

```
  note     the scan manifest was not written by the plugin's own writer
           keys are not in sorted order at the top level
           the file is mode 664, and the writer creates 600
           The content parses and the artifact digests above still match, so
           the findings themselves are readable and unchanged.
           Scans in this state have both failed to publish and published
           normally, so this is a reason to look rather than a verdict.
```

Those last two lines are the point. The first version of this check said such a
scan had been *refused* by the workbench, which sounded right and was wrong:
checking against real runs found eleven scans in this state and three of them
had published perfectly well. So it reports the fact and not a verdict, and
**does not fail verification** — a check that cries wolf is switched off, and
then it protects nothing.

It also does not offer to rewrite the file into canonical form. That is
resealing a document somebody else changed, which is the one thing a seal exists
to prevent.

## Knowing how a scan was produced

Every scan writes `provenance.json` beside its findings:

```json
{
  "tool": "puncode-security", "toolVersion": "0.1.0",
  "pluginVersion": "0.1.14", "pluginDigest": "d8fd28b6898c696f...",
  "model": "…", "endpoint": "http://host:8080/v1", "wireApi": "responses",
  "endpointAdaptations": ["merge-system"],
  "sandboxDisabled": true,
  "mode": "standard",
  "startedAt": "…", "completedAt": "…"
}
```

A `findings.json` says what was found and nothing about what found it. Handed
one a month later, you could not tell which model produced it, whether it ran
against a hosted service or a machine under a desk, or **whether the agent's
commands were sandboxed at the time**. That last one bears directly on how much
weight a report deserves, and it should not have to be guessed.

The plugin digest is there because two scans naming one plugin version could
still have run different code.

Credentials are removed from the endpoint before it is recorded — a URL can
carry a username and password, and a scan record is exactly the sort of file
that gets attached to a ticket.

## Comparing runs

```sh
puncode-security scan . --repeat 3 --output-dir ./scans
```

Runs three scans, one after another, into `scans/run-1..run-3`, then reports how
much they agreed. It says up front that this costs three times a single scan,
because that should not be discovered afterwards. Runs are sequential: several
at once against one endpoint contend, and the point is to see the model's own
variation rather than the effects of load.

A run that fails is named and the rest are still compared — a partial answer
beats none. The exit code reflects the findings, not the agreement: a finding
seen once is still a finding.

With `--capture-traffic`, each run gets its own file (`traffic-run-1.jsonl` and
so on). Sharing one would leave only the last, and the reason to capture while
repeating is to see *why* the runs differed.

The same comparison is available over scans you already have:

Scan the same code twice and you will not get the same answer. Findings appear
and vanish, severities move, and one flaw arrives under three different titles.
A reviewer reading a single report cannot tell which findings would survive a
second look.

```sh
puncode-security consensus run-a/ run-b/ run-c/
```

```
Comparing 6 runs of the same target

  6 of 6   OS Command Injection in /ping Route  critical
            also called: OS command injection via /ping endpoint
            also called: OS command injection via user-supplied 'host' parameter
            also called: User-supplied 'host' parameter is passed directly into
                         subprocess.check_output with shell=True, enabling OS
                         command injection.
  6 of 6   SQL Injection in /user Route  severity disputed: critical, high
            also called: SQL injection via /user endpoint
            also called: SQL query is built via string concatenation using request
                         parameter 'name', allowing SQL injection.

  2 distinct, 2 in every run, 0 in only one
  1 disagreed on severity
```

That is real output from six runs of one model over one fixture, and it shows
what this is actually for. The six runs produced **six different titles for each
flaw** — one of them a whole sentence. Grouped on wording that would read as a
dozen findings; grouped on location it is two, both unanimous.

It also shows what it did *not* do here. `0 in only one` means there was no
noise to cut: on this fixture the model was entirely stable, and filtering by
agreement would have gained nothing. What it surfaced instead was a severity the
runs genuinely disagreed about, which no single report would have revealed.

Findings are grouped by **where they point, never by how they are worded** — two
runs describing one flaw differently have found one flaw. Runs that disagree
about severity say so rather than one silently winning.

Nothing is discarded by default. `--min-agreement N` hides the rest, and says
how many it hid: a finding seen once may be the one that was looked at most
carefully, so dropping it is a choice to make deliberately rather than a default.

**Agreement measures stability, not correctness.** Runs sharing a blind spot
agree exactly as readily as runs being right, and repeated runs of one model
agree more easily than different models would. The output says so too, because
that is where the decision gets made.

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

It is embedded in the binary and unpacked once per version to
`~/.codex-security/bundled/`. That unpacked copy sits on disk between commands,
and a scan executes its scripts — so the tree is digested at unpack time and
verified before every reuse. A copy that no longer matches what the binary
ships is replaced, and the replacement is announced rather than done quietly:
something having changed under you is worth knowing even once it is fixed.

## Contributing

[HANDOFF.md](HANDOFF.md) carries the working knowledge that is not recoverable
from the commits: which names are interoperation rather than branding and must
never be renamed, why this environment needs `--yolo`, workbench constraints
that look like bugs, and three confident diagnoses that turned out to be wrong.
Worth reading before changing anything in `api/prompt.rs` or renaming anything.

## Licence

Apache-2.0, the same as the original project. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).
