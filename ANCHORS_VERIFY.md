# ANCHORS stream verifier

Standalone checker for [`ANCHORS.jsonl`](ANCHORS.jsonl) and [`ANCHORS.jsonl.digests.json`](ANCHORS.jsonl.digests.json). **Standard library only.** Takes **public HTTPS URLs** as input — no local checkout required.

## Distribution (canonical)

The canonical distribution is a **single file** fetched and executed directly. **Zero dependencies.**

```bash
curl -sLO https://raw.githubusercontent.com/aos-standard/catalog/anchors-verify-v0.11/anchors_verify.py
python3 anchors_verify.py --self-test
```

To pin a release, reference tag **`anchors-verify-v0.11`** in the URL (not `main`). Older tags (`anchors-verify-v0.10`, `v0.9`, `v0.8`, `v0.7`, `v0.6`, `v0.5`, `v0.4`, `v0.2`, `v0.1`) remain available for history. **Published tags are never re-pointed.**

**`anchors-verify-v0.3` was published pointing at the wrong commit and does not implement the `VERIFY PARTIAL` / `VERIFY UNPINNED` outcomes documented here. It is superseded by `v0.4` and left in place rather than re-pointed, because re-pointing a published tag would break the reproducibility this verifier exists to check.**

**Line splitting (v0.5):** Releases through **`anchors-verify-v0.4`** decoded UTF-8 and used `str.splitlines()`, which treats `\r`, VT, FF, FS, GS, RS, NEL, U+2028, and U+2029 as line boundaries and could **silently drop** separator-only fragments. Standalone separators inserted inside an attested prefix could therefore produce **byte-identical verification output** despite changed raw bytes. **`v0.5` splits on raw `b"\n"` only**, hashes and prefix comparison operate on **stored line bytes**, and segments that cannot be read as a record **fail closed** (never skipped). This limit and fix were reported by **`mohammedmessaoudene-cmd`** in [`aos-standard/catalog#1`](https://github.com/aos-standard/catalog/issues/1).

**OK predicate (v0.7):** Same input bytes may yield a different outcome under a newer verifier. A stream that was **`VERIFY PARTIAL` under `v0.6` and earlier can become `VERIFY OK` under `v0.7`** when the tip after the attested prefix contains only boundary event rows (or nothing). **Tags are not re-pointed** — pin the verifier tag you mean to cite.

**Row classification and `rule_version` (v0.8):** Same input bytes may yield a different outcome under a newer verifier. A stream that was **`VERIFY OK` or `VERIFY PARTIAL` under `v0.7` can become `VERIFY FAILED` under `v0.8`** when a row mixes a recognized boundary event with record-shaped fields (`asset_id`), or when `rule_version` is not the known value for that event. Unknown rule versions fail closed — not knowing a rule is not the same as the rule being satisfied. **Tags are not re-pointed.** This change is a classification narrowing, not a security-impact claim.

**Record typing (v0.9):** Same input bytes may yield a different outcome under a newer verifier. A stream that was **`VERIFY OK` or `VERIFY PARTIAL` under `v0.8` can become `VERIFY FAILED` under `v0.9`** when a recognized boundary event carries a record-shaped **key** (`asset_id`) of any JSON type, when a no-event row is missing `asset_id` or `asset_id` is not a string, or when an integer field (`line_count`, `byte_length`, `size_bytes`, `rows`) is a JSON `true`/`false`. Classification uses **key presence**, not value type. Rows that are neither a recognized boundary event nor a record are malformed — they do not silently drop out of the attested unit. **Tags are not re-pointed.** This is a typing narrowing, not a security-impact claim.

**Unterminated final line (v0.11):** Same input bytes may yield a different outcome under a newer verifier. A stream whose final line has no trailing newline byte was hashed as if it had one through v0.10; under v0.11 it is hashed as stored, so such a stream that was VERIFY PARTIAL can become VERIFY FAILED (digest mismatch at the final line). Tags are not re-pointed. This is a byte-faithfulness fix against the text as written, not a security-impact claim.

This verifier is **not distributed as a PyPI package.** Requiring `pip install` would ask auditors to trust the supply chain; a single file can be read in full before execution.

**Run (copy-paste — tag-fixed, reproducible):**

```bash
curl -sLO https://raw.githubusercontent.com/aos-standard/catalog/anchors-verify-v0.11/anchors_verify.py
curl -sLO https://raw.githubusercontent.com/aos-standard/catalog/anchors-verify-v0.11/ANCHORS.jsonl
curl -sLO https://raw.githubusercontent.com/aos-standard/catalog/anchors-verify-v0.11/ANCHORS.jsonl.digests.json
python3 anchors_verify.py \
  --anchors-url file://$(pwd)/ANCHORS.jsonl \
  --digests-url file://$(pwd)/ANCHORS.jsonl.digests.json \
  --expect-witness-repo aos-standard/catalog
```

The bundled files come from the **same tag** as the verifier. You can reproduce without referencing `main`.

**Self-test (adversarial vectors, no network):**

```bash
python3 anchors_verify.py --self-test
```

**Optional — verify live `main` tip (not tag-fixed):**

Use this only when you intentionally want the moving witness stream on `main`. Results depend on how many lines exist on `main` at fetch time.

```bash
python3 anchors_verify.py \
  --anchors-url https://raw.githubusercontent.com/aos-standard/catalog/main/ANCHORS.jsonl \
  --digests-url https://raw.githubusercontent.com/aos-standard/catalog/main/ANCHORS.jsonl.digests.json \
  --expect-witness-repo aos-standard/catalog
```

## Verification outcomes (do not conflate)

**Contract change (v0.4):** Prior releases through `v0.2` (and the mis-pointed `v0.3` tag) treated partial attestation like full success (`VERIFY OK` with `attested_prefix_lines < lines`). **`v0.4` adds distinct outcomes and exit codes.**

**Contract change (v0.11):** The final line is hashed as stored. No byte is added before hashing.

**Contract change (v0.9):** Row interpretation treats a no-event row as a record and fails closed if `asset_id` is missing or not a string, or if integer fields are JSON booleans. A recognized boundary event that carries the `asset_id` **key** (any value type) is malformed. Unattested tip rows of any shape cannot produce `VERIFY OK`.

**Contract change (v0.8):** Row interpretation fails closed before boundary or attested-unit checks. A recognized boundary event (`witness_ref_introduced`, `signature_suite_introduced`, `position_binding_introduced`) that also carries record-shaped fields (`asset_id`) is **malformed**, not classified as either side. `rule_version` is accepted only from the event correspondence table (`witness-ref-v1` / `signature-suite-v1` / `position-binding-v1`); any other value fails closed.

**Contract change (v0.7):** `VERIFY OK` no longer requires `attested_prefix_lines == lines`. **`prefix.line_count` still means the first N lines** (byte comparison unchanged). OK means the **attested unit** has no unattested tip:

> **Attested unit** = every anchor record row, excluding the boundary events `witness_ref_introduced`, `signature_suite_introduced`, and `position_binding_introduced`.

| Outcome | Exit code | Meaning |
|---------|-----------|---------|
| **VERIFY OK** | 0 | Attested prefixes byte-match the witness platform, and **no anchor record row exists after the last attested prefix**. Boundary event rows after that prefix are allowed. **OK appears only in the window immediately after an attestation and before the next record append.** |
| **VERIFY PARTIAL** | 3 | Some prefix is attested and verified, but **at least one anchor record row sits after the attested prefix** (typical weekly tip). **PARTIAL is the healthy steady state in rolling operation** — it does not mean the verifier is broken. **Not full verification.** |
| **VERIFY UNATTESTED** | 2 | Digest and boundary checks passed, but **`attested_prefix_lines=0`** — no position binding. Not a successful verification. |
| **VERIFY UNPINNED** | 4 | Digest/binding checks may have run, but **`--expect-witness-repo` was omitted** — trust anchor taken from the stream itself. **Not citable as anchored verification.** |
| **VERIFY FAILED** | 1 | Digest mismatch, boundary violation, **malformed hybrid row**, **malformed record** (missing/`asset_id` not a string, or integer field is a bool), **unknown `rule_version`**, prefix mismatch, trust-anchor mismatch, or binding commit **not reachable** from the pin repository's default-branch history (or ancestry could not be confirmed). |

**Do not treat PARTIAL, UNATTESTED, or UNPINNED as OK.** **Do not treat “OK is absent on a growing tip” as a defect.**

## What it checks

- Each JSONL line SHA-256 matches the sidecar entry for that line index. Hashes cover the **full stored line including the trailing newline byte**, computed on **raw bytes** (not Unicode-normalized line strings).
- A final line with no trailing newline byte is hashed as stored; a digest computed over the same line with a newline byte does not match it.
- Lines are split on **`b"\n"` only** — no `str.splitlines()` normalization.
- Invalid or separator-only lines are **not skipped**; they fail closed via digest mismatch or parse rejection.
- Boundary rules for `witness_ref_introduced`, `signature_suite_introduced`, and `position_binding_introduced` (field presence before/after each event).
- **Row classification (v0.8 / v0.9):** a recognized boundary event together with record-shaped **keys** (`asset_id`, any JSON type) is malformed (fail closed). Errors name the line number, the event, and the record fields. A no-event row missing `asset_id`, or with a non-string `asset_id`, is malformed — it is not ignored.
- **Integer fields (v0.9):** `line_count`, `byte_length`, `size_bytes`, and `rows` reject JSON booleans (`true` is not `1`).
- **`rule_version` (v0.8):** only the three known event↔version pairs are accepted. Unknown or mismatched values fail closed.
- **Truncation vector 1:** fewer anchor lines than digest entries → fail closed.
- **Truncation vector 2 (unattested tip only):** anchor lines and sidecar both shortened but internally consistent → fail closed **when compared to witness platform snapshots** on lines **after** the last `position_binding_introduced` attestation.
- **Position binding (attested prefix):** for each `position_binding_introduced` event, the verifier fetches `ANCHORS.jsonl` at the named witness commit and checks that the attested **prefix length, byte length, and SHA-256** match **byte-for-byte** on the witness platform and in the presented stream. Inserted fake boundaries inside an attested prefix are detected.
- **Witness commit history (v0.7):** name match alone is insufficient. Each binding commit must be **reachable from the pin repository's default branch** via `GET /repos/{repo}/compare/{default_branch}...{sha}` with **`ahead_by == 0`** (ancestor or identical). Commits that exist only under `refs/pull/N/head` (fork PR heads) fail closed. Do **not** use “which branches have this SHA as tip” queries — legitimate ancestor commits are not branch heads. If ancestry cannot be confirmed (network, API limits, malformed responses), the verifier **does not** return OK or PARTIAL.

## Trust anchor (`--expect-witness-repo`)

**Required for VERIFY OK or VERIFY PARTIAL.** Supply the witness repository as `owner/repo` (e.g. `aos-standard/catalog`). The verifier uses this as the trust anchor for platform queries instead of accepting whatever repository the stream under verification names.

- If `--expect-witness-repo` is set and the stream names a different repository → **fail closed** (`VERIFY FAILED`).
- If set, each binding commit must also lie on that repository's **default-branch history** (`ahead_by == 0`); otherwise **fail closed**. Unconfirmable ancestry → **fail closed** (never OK/PARTIAL).
- If omitted → **warning** plus **`VERIFY UNPINNED`** (exit 4): a forged stream can point queries at an attacker-controlled repository.

## Rolling attestation discipline

Each sync that changes `ANCHORS.jsonl` should append a `position_binding_introduced` event naming the **witness commit that contains the previous sync** (the commit one step behind the append), plus the **prefix line count, byte length, and digest** of the material being attested. The latest append remains unattested until the next event arrives.

## Limits (read before citing results)

Do **not** claim unconditional fork blocking. The following remain out of scope:

| Limit | Reason |
|-------|--------|
| **Unattested stream tip** | The latest append is not bound until the next `position_binding_introduced` arrives. **Forks at the tip are not detectable.** |
| **Equivocation** | No signature suite is implemented. Conflicting continuations signed by the same key cannot be attributed. |
| **Force-push** | If witness repository history is rewritten, history-dependent checks break. |
| **OK only in a short window** | After the next anchor record is appended, the tip is again outside the attested unit until a new `position_binding_introduced` arrives. Weekly tips with fresh records are expected to report **PARTIAL**. |

What this tool **does** buy: **detection of fake boundaries inserted after the fact within an attested prefix**, plus **rejection of binding commits outside the pin repository's default-branch history** — not discrimination between two equivalent continuations shown to different auditors.

- **Signature verification is not implemented.** The stream may declare `signature_suite`; this tool does not validate signatures or keys.
- **Truncation vector 2 on the unattested tip** depends on witness platform history not being rewritten. Do **not** claim unconditional truncation detection.
- **Through v0.4:** Unicode line-boundary normalization could miss standalone separator injection inside attested prefixes (see distribution note above). Use **`anchors-verify-v0.5`** or later for raw-byte line splitting.

Detection strength inherits the availability and honesty of the witness platform whose history you compare against, and whether you supply `--expect-witness-repo`.
