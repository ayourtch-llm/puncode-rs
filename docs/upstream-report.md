# A contract the agent is never told about

A report for [github.com/openai/codex-security](https://github.com/openai/codex-security),
written while porting the package to Rust and running it against a local 35B
model. Everything below is checked against the shipped package in this
checkout rather than recalled; the commands to re-check each claim are included.

## What happens

A scan does all of its work — inventory, discovery, validation, write-up — and
then fails on the last step with one of:

```
scan-manifest.json target kind must match the workbench target.
scan-manifest.json scope must match the workbench scan scope.
```

Nothing is saved. The findings are correct and on disk, the workbench has no
record, and the cost has already been paid. On a hosted model this is an
annoyance. On a local one, where a scan is twenty to forty minutes, it is most
of an afternoon.

## Why

`workbench_db.py` requires the manifest's `target.kind` to be one of a set it
computes itself:

```python
# scripts/workbench_db.py:679
if target.get("kind") not in expected_target["allowedKinds"]:
    raise SystemExit("scan-manifest.json target kind must match the workbench target.")
```

`allowedKinds` depends on a registration snapshot compared against the working
tree *now* — whether the tree is clean, whether the revision is `unversioned`,
whether the snapshot digest still matches. An agent cannot derive it from the
repository in front of it, and there is no reason it would guess the same answer
the workbench did.

**It is never told.** `allowedKinds` appears in exactly one file in the whole
package:

```sh
grep -rln "allowedKinds" .
# sdk/typescript/_bundled_plugin/scripts/workbench_db.py
```

Thirteen skills ship. None mentions the workbench contract, `allowedKinds`, or
`workbench_db.py get-scan` — the command that would answer the question:

```sh
grep -rl "allowedKinds\|contract.target\|get-scan\|workbench_db" --include=SKILL.md .
# (no output)
```

`security-scan/SKILL.md` names exactly one script for the agent to run, and it is
not that one:

```sh
grep -rhoE "scripts/[a-z_]+\.py" .../skills/security-scan/SKILL.md
# scripts/finalize_scan_contract.py
```

So the requirement exists, is enforced at the last possible moment, is not
computable from the repository, and is not written down anywhere the agent
reads. A strong model recovers by exploring the plugin directory. A weaker one
does not, and cannot be blamed for it.

## The schemas do not help either

The scan contract is defined by three JSON Schema documents, and they carry no
prose at all:

```sh
# 0 of 141 schema properties carry a description
```

`includePaths` and `excludePaths` are the clearest case. Both are `{"type":
"array"}` in `scan-manifest.schema.json` and `coverage.schema.json`, with nothing
saying they must equal what the workbench registered, or what a path is relative
to. The workbench is not vague about it at all — `scan_contract` returns

```python
"scope": {
    "requiredExcludePaths": [],
    "requestedPath": scan["scope"],
    "requiredIncludePaths": requested_scan_paths(scan),   # non-diff scans
}
```

so an empty `excludePaths` is *required*, not merely permitted, and the fields
are even named `required…`. That is enforced at `workbench_db.py:727` and
appears in no schema and no skill.

An agent reading a schema to learn a contract learns the shape and none of the
meaning.

## Suggested fix, in the order I would do it

1. **Say it in the scan skills.** One paragraph in `security-scan/SKILL.md` and
   its deep and diff variants: before writing the manifest, run
   `workbench_db.py get-scan <id>` and take `contract.target.allowedKinds`,
   `contract.scope.requiredIncludePaths` and `contract.scope.requiredExcludePaths`
   from it rather than inferring them. `get-scan` already returns all of it under
   `contract`; nothing new has to be built. This is the whole fix for most runs.

2. **Describe the contract fields in the schemas.** Especially `target.kind`,
   `scope.includePaths` and `scope.excludePaths`. A description on a schema
   property is the cheapest documentation there is, and it reaches any agent
   that reads the schema.

3. **Check earlier.** `allowedKinds` and the scope are known when the scan is
   registered. Validating the manifest's target and scope as soon as the
   manifest is first written, rather than at publication, turns forty wasted
   minutes into a correctable error.

## What worked here

Stating what the port already knows and asking for what it cannot compute. The
Rust port adds two lines to the prompt: one naming the registered scope, and one
telling the agent to read the target contract with
`workbench_db.py get-scan → contract.target.allowedKinds`. After that the same
local model completed scans it had been failing on for the same reason every
time.

The second line is the interesting one. The port deliberately does **not**
compute the target kind itself, because doing so would mean reimplementing the
plugin's digest and cleanliness logic and would drift from it. Asking the
workbench is both simpler and correct — but only the plugin knows to ask.

## A second, related conflict

The scan skills ask the agent to confirm a finding by running the code. The
workbench hashes the working tree and refuses to record a scan whose contents
changed:

```
Could not save the Puncode Security scan: Working-tree contents changed
while the scan was running. Start a new scan.
```

On any repository with a build step those two requirements are in direct
conflict. A scan of a small C project here failed exactly this way: the agent
ran `make` to confirm a memory-safety finding, the binary landed beside the
source, and the whole scan was refused at the end. `git status` afterwards:

```
?? store
```

The agent did nothing wrong, the check is doing its job, and the scan is lost
anyway. Same shape as the contract problem above — enforced at publication,
after all the work.

Worth either telling the agent to build outside the tree, or hashing only the
paths in scope, or excluding files that did not exist when the scan started.

## Reproducing

Any model that does not go exploring will do. The failures here were with
`deepreinforce-ai_Ornith-1.0-35B` over an OpenAI-compatible endpoint, but nothing
about the problem is model-specific: the information is not present in what the
agent is given.
