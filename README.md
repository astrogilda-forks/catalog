# AOS Public Catalog

Machine-readable product catalog and trust artifacts for [AOS-v0.1](https://github.com/aos-standard/AOS-spec) tools.

| File | Purpose |
|------|---------|
| [`catalog.json`](catalog.json) | Product entries (install, pricing, MCP endpoints) |
| Payment instructions | In [`catalog.json`](catalog.json) (`products[].payment`). Locator only — not a call to action. |
| [`governance.json`](governance.json) | Structure audit evidence (measured at export time) |
| [`precedents.json`](precedents.json) | Public summaries of business-pattern precedents |
| [`ANCHORS.jsonl`](ANCHORS.jsonl) | Weekly SHA-256 anchors for private assets |
| [`anchors_verify.py`](anchors_verify.py) | **Public URL verifier** for ANCHORS + digest sidecar ([how to run](ANCHORS_VERIFY.md)) — **single-file `curl` distribution**; pin with tag [`anchors-verify-v0.8`](https://github.com/aos-standard/catalog/releases/tag/anchors-verify-v0.8) (not PyPI) |
| [`t2_constructions.py`](t2_constructions.py) | **T2 construction set** — ten mutations plus baseline (not “nine”; miscount corrected) with regenerated sidecars; see [`T2_CONSTRUCTIONS.md`](T2_CONSTRUCTIONS.md); pin with tag [`anchors-verify-v0.6`](https://github.com/aos-standard/catalog/releases/tag/anchors-verify-v0.6) |
| [`attestations/`](attestations/) | **Signed audit badges** for MCP servers that opt in via [badge application](https://github.com/aos-standard/mcp-blast-radius/issues/new?template=badge-application.yml) |
| [`CONDUCT.jsonl`](CONDUCT.jsonl) | **Verification conduct ledger** — append-only record of self-found defects, external breaks, refutations, and tag-integrity events. Free. **Not a KPI** (row count is not a score). How to read: [`CONDUCT.md`](CONDUCT.md). A paid SKU, if offered later, is third-party artifact judgment — not this ledger |
| [`CONDUCT.md`](CONDUCT.md) | Reader guide for `CONDUCT.jsonl`: `public` vs `internal_only` evidence, limits, and non-KPI framing |

**Audit badge program:** Free, opt-in, 90-day attestations — see [mcp-blast-radius BADGE_CRITERIA.md](https://github.com/aos-standard/mcp-blast-radius/blob/main/BADGE_CRITERIA.md).

Maintainer: Tetsuroh Hori (Tetsurohhori)
