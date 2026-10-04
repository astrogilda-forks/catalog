# Verification Conduct Ledger

Append-only record of verification conduct by aos-standard: defects we found in our own
tools, defects others broke open, external refutations, and tag-integrity events.
`claim_contradicted_published` is a published observation that disagreed with the
target's own declaration. `self_found` stays a record of our own defect.
A published independent reproduction of **someone else's** stated claim, where the claim held
within the stated coverage. Not an endorsement of the target's work as a whole, and not a
statement about correctness — only that the stated property reproduced under the conditions
recorded in the row.

Companion file: [`CONDUCT.jsonl`](CONDUCT.jsonl) (one JSON object per line).

## What this is

- A **free**, machine-readable history of verification behavior.
- Evidence for why a later paid judgment service (third-party artifact review) could be
  worth trusting — **accumulation first, sale later**.

## What this is not

- **Not a KPI.** More rows is not “better.” Do not treat `entry_id` count or row count as a score.
- **Not a paid stamp** on our own tools. Self-attestation is out of scope.
- **Not a closed suite.** Closing the verification surface would collapse this ledger back
  into self-declaration.

## `evidence` values (do not conflate)

| Value | Meaning | Reader can verify? |
|-------|---------|--------------------|
| `public` | `public_urls` non-empty and `digest` present | **Yes** — fetch URLs, check digest (recipe below) |
| `internal_only` | `public_urls` empty; `unverifiable_by_reader` is true | **No** — class-level disclosure only |

Mixing these shapes is a schema failure: export refuses the file. Readers are not asked to
“be careful”; the format makes the classes mechanically distinct.

`claim_reproduced_published` is `evidence: public` only. Its `resolution.state` is
`unresolved` only, meaning nothing to resolve: no defect was found.

## How to verify a `digest` (reader recipe)

Read each row's `digest.of`. Two shapes are in use:

### A. GitHub comment body (exact UTF-8 bytes)

`of` names an issues-comments API URL. Hash **only** `payload["body"]` — not the full JSON
(reactions, `updated_at`, and similar fields are intentionally excluded).
An issue body is the same material as a comment body: hash `payload["body"]` from the issues API
the same way, and do not append a trailing newline.

```bash
curl -sS https://api.github.com/repos/<owner>/<repo>/issues/comments/<id> \
  | python3 -c 'import json,sys,hashlib; print(hashlib.sha256(json.load(sys.stdin)["body"].encode("utf-8")).hexdigest())'
```

Compare the printed hex to `digest.sha256`. A reaction emoji on the comment must not change it.
A body edit must change it (that is a real content change).

### C. One probes `rows.jsonl` line

`of` names the public file URL and the row `name`. Hash the UTF-8 bytes of that
single JSON line, excluding the line terminator.

```bash
python3 -c '
import hashlib, json, sys, urllib.request
url, name = sys.argv[1], sys.argv[2]
text = urllib.request.urlopen(url).read().decode("utf-8")
for line in text.splitlines():
    if json.loads(line).get("name") == name:
        print(hashlib.sha256(line.encode("utf-8")).hexdigest())
        break
' 'https://raw.githubusercontent.com/aos-standard/catalog/main/probes/batch_2026-09-28/rows.jsonl' 'io.github.bleedmode/dearuser'
```

### B. `git ls-remote --tags` lines (tag integrity)

When `of` describes sorted `git ls-remote --tags` lines for named refs, reproduce exactly as
written in `of` (same refs, sorted, newline-terminated), then sha256 the UTF-8 bytes.

```bash
git ls-remote --tags https://github.com/aos-standard/catalog.git \
  | grep -E 'refs/tags/anchors-verify-v0\.[23]$' \
  | sort \
  | python3 -c 'import sys,hashlib; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'
```

## Limits (same family as `anchors_verify.py`)

- The stream **tip** may be unattested until the next position-binding event.
- **Force-push** on a witness repository is outside what this ledger can prevent.
- `internal_only` rows are honest about unreadability; they are not substitutes for `public` rows.

## Paid SKU boundary

This ledger is free. A paid verification SKU, if offered later, is **judgment of third-party
artifacts**, not a fee to stamp our own repositories.
