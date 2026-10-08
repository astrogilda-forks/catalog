#!/usr/bin/env python3
"""Verify ANCHORS.jsonl + digest sidecar from public URLs (stdlib only).

Each JSONL line hash includes the trailing newline byte(s) as stored on disk.
Signature verification is not implemented (signature_suite parameter only).

Position binding detects inserted fake boundaries within attested prefixes.
The stream tip before the next attestation remains unattested (fork at tip
is not detectable). Equivocation and force-push are not prevented.
"""

from __future__ import annotations

from pathlib import Path
import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
import warnings
from typing import Any, Callable

WITNESS_EVENT_NAME = "witness_ref_introduced"
SIGNATURE_SUITE_EVENT_NAME = "signature_suite_introduced"
POSITION_BINDING_EVENT_NAME = "position_binding_introduced"
DIGEST_SUITE_TRANSITION_EVENT_NAME = "digest_suite_transition"
DEFAULT_SIGNATURE_SUITE_NONE = "none"

SUITE_KECCAK256_JCS = "keccak256-jcs"
SUITE_SHA3_256_JCS = "sha3-256-jcs"

VERIFY_ERROR = "verify_error"

LIMITATIONS_TEXT = (
    "Limits: attested-prefix fork detection only (tip unattested until next "
    "attestation); no equivocation attribution without signatures; force-push "
    "on witness repo breaks history-dependent checks."
)


class VerifyError(Exception):
    """Verification failed — fail closed."""


class VerifyUnattested(Exception):
    """Digest/boundary checks passed but no position_binding attestation exists."""


EXIT_OK = 0
EXIT_FAILED = 1
EXIT_UNATTESTED = 2
EXIT_PARTIAL = 3
EXIT_UNPINNED = 4


def _fail(message: str) -> None:
    raise VerifyError(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_line(line: bytes | str) -> str:
    if isinstance(line, str):
        return sha256_bytes(line.encode("utf-8"))
    return sha256_bytes(line)


def fetch_url(url: str, *, timeout: float = 60.0) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "aos-anchors-verify/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        _fail(f"HTTP {exc.code} fetching {url}")
    except urllib.error.URLError as exc:
        _fail(f"network error fetching {url}: {exc.reason}")
    raise AssertionError("unreachable")


def bytes_to_lines(content: bytes) -> list[bytes]:
    """Split on b'\\n' only; each line carries the newline byte it stores on disk.

    No Unicode line-boundary normalization — raw stored bytes are preserved.
    A final line that stores no trailing newline byte is returned as stored: no
    byte is appended, so its digest does not match the same line carrying one.
    Separator-only segments are retained (never silently skipped).
    """
    if not content:
        return []
    parts = content.split(b"\n")
    lines: list[bytes] = []
    for index, part in enumerate(parts):
        is_last = index == len(parts) - 1
        if is_last and part == b"" and content.endswith(b"\n"):
            continue
        if is_last and not content.endswith(b"\n"):
            if not part:
                _fail("empty anchor line")
            lines.append(part)
        else:
            lines.append(part + b"\n")
    return lines


def parse_row(line: bytes) -> dict[str, Any]:
    try:
        text = line.decode("utf-8")
    except UnicodeDecodeError as exc:
        _fail(f"invalid UTF-8 in anchor line: {exc}")
    stripped = text.strip()
    if not stripped:
        _fail("empty anchor line")
    try:
        row = json.loads(stripped)
    except json.JSONDecodeError as exc:
        _fail(f"invalid JSONL line: {exc}")
    if not isinstance(row, dict):
        _fail("anchor line must be a JSON object")
    return row


def is_witness_introduction_event(row: dict[str, Any]) -> bool:
    return row.get("event") == WITNESS_EVENT_NAME


def is_signature_suite_introduction_event(row: dict[str, Any]) -> bool:
    return row.get("event") == SIGNATURE_SUITE_EVENT_NAME


def is_position_binding_introduction_event(row: dict[str, Any]) -> bool:
    return row.get("event") == POSITION_BINDING_EVENT_NAME


def is_digest_suite_transition_event(row: dict[str, Any]) -> bool:
    return row.get("event") == DIGEST_SUITE_TRANSITION_EVENT_NAME


def is_versioned_boundary_event(row: dict[str, Any]) -> bool:
    return (
        is_witness_introduction_event(row)
        or is_signature_suite_introduction_event(row)
        or is_position_binding_introduction_event(row)
        or is_digest_suite_transition_event(row)
    )


# Event name → the only accepted rule_version. Unknown values fail closed.
# Do not treat "this rule is unknown" as "this rule is satisfied".
KNOWN_BOUNDARY_RULE_VERSIONS: dict[str, str] = {
    WITNESS_EVENT_NAME: "witness-ref-v1",
    SIGNATURE_SUITE_EVENT_NAME: "signature-suite-v1",
    POSITION_BINDING_EVENT_NAME: "position-binding-v1",
    DIGEST_SUITE_TRANSITION_EVENT_NAME: "suite-transition-v1",
}

# Fields that make a row record-shaped. Presence together with a recognized
# boundary event is malformed — do not classify as either side.
# Presence of the key is enough; the value's type is not consulted.
RECORD_SHAPE_FIELDS: tuple[str, ...] = ("asset_id",)

# Integer payload keys on record rows. Absent is allowed; present must be a
# JSON integer (bool is not an integer).
RECORD_INTEGER_FIELDS: tuple[str, ...] = ("size_bytes", "rows")


def is_json_int(value: Any) -> bool:
    """True for JSON integers. bool is a subclass of int in Python — reject it."""
    return isinstance(value, int) and not isinstance(value, bool)


def record_shape_fields_present(row: dict[str, Any]) -> list[str]:
    present: list[str] = []
    for key in RECORD_SHAPE_FIELDS:
        if key in row:
            present.append(key)
    return present


def is_malformed_hybrid_row(row: dict[str, Any]) -> bool:
    return is_versioned_boundary_event(row) and bool(record_shape_fields_present(row))


def require_known_rule_version(
    row: dict[str, Any],
    *,
    line_no: int | None = None,
) -> str:
    loc = f" at line {line_no}" if line_no is not None else ""
    event = row.get("event")
    expected = (
        KNOWN_BOUNDARY_RULE_VERSIONS.get(event) if isinstance(event, str) else None
    )
    actual = row.get("rule_version")
    if expected is None:
        _fail(f"rule_version not applicable{loc}")
    if not isinstance(actual, str) or not actual:
        _fail(f"{event} event missing rule_version{loc}")
    if actual != expected:
        _fail(
            f"unknown rule_version {actual!r}{loc} for event {event!r} "
            f"(known: {expected})"
        )
    return actual


def require_anchor_record(row: dict[str, Any], *, line_no: int) -> None:
    """Fail closed when a no-event row is not a well-formed record.

    Rows without ``event`` are records. They are never a third state that
    silently drops out of the attested unit. Type of ``asset_id`` is checked
    here, not at classification.
    """
    if "asset_id" not in row:
        _fail(f"malformed record at line {line_no}: missing asset_id")
    if not isinstance(row.get("asset_id"), str):
        _fail(
            f"malformed record at line {line_no}: asset_id must be a string "
            f"(got {type(row.get('asset_id')).__name__})"
        )
    for key in RECORD_INTEGER_FIELDS:
        if key not in row:
            continue
        if not is_json_int(row[key]):
            _fail(
                f"malformed record at line {line_no}: {key} must be an integer "
                f"(bool is not an integer)"
            )


def interpret_anchor_row(row: dict[str, Any], *, line_no: int) -> None:
    """Fail closed on hybrid rows, unknown events, malformed records, unknown rule_version.

    A row is a boundary event, a record, or malformed. There is no third class.
    """
    if is_versioned_boundary_event(row):
        fields = record_shape_fields_present(row)
        if fields:
            _fail(
                f"malformed row at line {line_no}: recognized boundary event "
                f"{row.get('event')!r} together with record fields {fields}"
            )
        require_known_rule_version(row, line_no=line_no)
        return
    if "event" in row:
        _fail(f"unknown event at line {line_no}")
    require_anchor_record(row, line_no=line_no)
    actual = row.get("rule_version")
    if isinstance(actual, str) and actual:
        known = set(KNOWN_BOUNDARY_RULE_VERSIONS.values())
        if actual not in known:
            _fail(f"unknown rule_version {actual!r} at line {line_no}")


def interpret_anchor_lines(lines: list[bytes]) -> None:
    for index, line in enumerate(lines):
        interpret_anchor_row(parse_row(line), line_no=index + 1)


def is_anchor_record(row: dict[str, Any]) -> bool:
    """True when the row is classified as a record (no ``event`` key).

    Well-formedness (string ``asset_id``, integer fields) is enforced by
    ``require_anchor_record`` / ``interpret_anchor_row``. Classification
    does not inspect value types — that was the third state that dropped
    tip rows out of the attested unit.
    """
    return "event" not in row


def attested_unit_fully_covered(
    presented_lines: list[bytes],
    attested_prefix_lines: int,
) -> bool:
    """Return True when VERIFY OK's attested-unit predicate holds (v0.7).

    Attested unit = every row that is not a recognized boundary event
    (`witness_ref_introduced`, `signature_suite_introduced`,
    `position_binding_introduced`). Malformed or mistyped records still
    count: they must not vanish into a third state.

    OK when no such row exists after the attested prefix. Boundary
    event rows after the prefix are allowed. This does **not** change
    `prefix.line_count` semantics (still byte-compare `presented_lines[:N]`).
    """
    if attested_prefix_lines < 1:
        return False
    if attested_prefix_lines > len(presented_lines):
        return False
    for line in presented_lines[attested_prefix_lines:]:
        row = parse_row(line)
        if not is_versioned_boundary_event(row):
            return False
    return True


def load_active_witness(lines: list[bytes]) -> dict[str, Any] | None:
    witness: dict[str, Any] | None = None
    for index, line in enumerate(lines):
        row = parse_row(line)
        if not is_witness_introduction_event(row):
            continue
        if witness is not None:
            _fail("multiple witness_ref_introduced events")
        candidate = row.get("witness")
        if not isinstance(candidate, dict):
            _fail("witness_ref_introduced event missing witness object")
        require_known_rule_version(row, line_no=index + 1)
        witness = candidate
    return witness


def witness_record_matches_active(record_witness: Any, active_witness: dict[str, Any]) -> bool:
    if not isinstance(record_witness, dict):
        return False
    for key in ("kind", "repo", "commit"):
        if record_witness.get(key) != active_witness.get(key):
            return False
    return True


def verify_witness_boundary(lines: list[bytes]) -> None:
    boundary_index: int | None = None
    active_witness: dict[str, Any] | None = None
    for index, line in enumerate(lines):
        row = parse_row(line)
        if is_witness_introduction_event(row):
            if boundary_index is not None:
                _fail("multiple witness_ref_introduced events")
            boundary_index = index
            active_witness = load_active_witness(lines)
            continue
        if (
            is_signature_suite_introduction_event(row)
            or is_position_binding_introduction_event(row)
            or is_digest_suite_transition_event(row)
        ):
            continue
        if "event" in row:
            _fail(f"unknown event at line {index + 1}")
        if not is_anchor_record(row):
            _fail(f"unrecognized record at line {index + 1}")

        has_witness = "witness" in row
        if boundary_index is None:
            if has_witness:
                _fail(f"witness before introduction at line {index + 1}")
            continue
        if index < boundary_index:
            if has_witness:
                _fail(f"witness before introduction at line {index + 1}")
        elif index > boundary_index:
            if not has_witness:
                _fail(f"missing witness after introduction at line {index + 1}")
            if active_witness is None or not witness_record_matches_active(
                row.get("witness"), active_witness
            ):
                _fail(f"witness mismatch at line {index + 1}")


def load_active_signature_suite(lines: list[bytes]) -> str | None:
    suite: str | None = None
    for index, line in enumerate(lines):
        row = parse_row(line)
        if not is_signature_suite_introduction_event(row):
            continue
        if suite is not None:
            _fail("multiple signature_suite_introduced events")
        require_known_rule_version(row, line_no=index + 1)
        candidate = row.get("signature_suite")
        if not isinstance(candidate, str) or not candidate:
            _fail("signature_suite_introduced event missing signature_suite")
        suite = candidate
    return suite


def verify_signature_suite_boundary(lines: list[bytes]) -> None:
    boundary_index: int | None = None
    active_suite: str | None = None
    for index, line in enumerate(lines):
        row = parse_row(line)
        if is_versioned_boundary_event(row):
            if is_signature_suite_introduction_event(row):
                if boundary_index is not None:
                    _fail("multiple signature_suite_introduced events")
                boundary_index = index
                active_suite = load_active_signature_suite(lines)
            continue
        if "event" in row:
            _fail(f"unknown event at line {index + 1}")
        if not is_anchor_record(row):
            _fail(f"unrecognized record at line {index + 1}")

        has_suite = "signature_suite" in row
        if boundary_index is None:
            if has_suite:
                _fail(f"signature_suite before introduction at line {index + 1}")
            continue
        if index < boundary_index:
            if has_suite:
                _fail(f"signature_suite before introduction at line {index + 1}")
        elif index > boundary_index:
            if not has_suite:
                _fail(f"missing signature_suite after introduction at line {index + 1}")
            if active_suite is None or row.get("signature_suite") != active_suite:
                _fail(f"signature_suite mismatch at line {index + 1}")


# --- Vendored Keccak-256 (Ethereum padding; not hashlib.sha3_256) -----------------
_KECCAK_MASK = (1 << 64) - 1
_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_KECCAK_ROT = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
]


def _keccak_rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _KECCAK_MASK


def _keccak_f(state):
    for rnd in range(24):
        c = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _keccak_rotl(c[(x + 1) % 5], 1) for x in range(5)]
        state = [[state[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _keccak_rotl(state[x][y], _KECCAK_ROT[x][y])
        state = [
            [b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)]
            for x in range(5)
        ]
        state[0][0] ^= _KECCAK_RC[rnd]
    return state


def _keccak256(data: bytes) -> bytes:
    rate = 136
    padded = bytearray(data)
    padlen = rate - (len(padded) % rate)
    if padlen == 1:
        padded += b"\x81"
    else:
        padded += b"\x01" + b"\x00" * (padlen - 2) + b"\x80"
    state = [[0] * 5 for _ in range(5)]
    for offset in range(0, len(padded), rate):
        for lane_index in range(rate // 8):
            lane = int.from_bytes(
                padded[offset + 8 * lane_index : offset + 8 * lane_index + 8],
                "little",
            )
            state[lane_index % 5][lane_index // 5] ^= lane
        state = _keccak_f(state)
    digest = bytearray()
    for lane_index in range(rate // 8):
        digest += state[lane_index % 5][lane_index // 5].to_bytes(8, "little")
        if len(digest) >= 32:
            break
    return bytes(digest[:32])


for _kat_msg, _kat_want in {
    b"": "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    b"abc": "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
}.items():
    if _keccak256(_kat_msg).hex() != _kat_want:
        raise RuntimeError("vendored keccak256 self-check failed")


def _norm_hex_digest(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    lowered = value.lower()
    if not lowered.startswith("0x") or len(lowered) != 66:
        return None
    try:
        int(lowered[2:], 16)
    except ValueError:
        return None
    return lowered


def _auec_canonical(value: Any) -> str:
    """RFC 8785-style canonical form for conformance-vector AUEC prefix records."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, int):
        if abs(value) > 2**53 - 1:
            _fail("AUEC prefix integer outside I-JSON interoperable range")
        return str(value)
    if isinstance(value, float):
        _fail("AUEC prefix digest domain rejects non-integer JSON numbers")
    if isinstance(value, list):
        return "[" + ",".join(_auec_canonical(item) for item in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(
            json.dumps(key, ensure_ascii=False) + ":" + _auec_canonical(val)
            for key, val in items
        ) + "}"
    _fail(f"AUEC prefix contains non-JSON value: {type(value).__name__}")
    raise AssertionError("unreachable")


def _auec_prefix_digest(prefix: list[Any], suite: str) -> str:
    canonical_bytes = _auec_canonical(prefix).encode("utf-8")
    if suite == SUITE_KECCAK256_JCS:
        return "0x" + _keccak256(canonical_bytes).hex()
    if suite == SUITE_SHA3_256_JCS:
        return "0x" + hashlib.sha3_256(canonical_bytes).hexdigest()
    _fail(f"unknown digest suite {suite!r}")
    raise AssertionError("unreachable")


def verify_digest_suite_transitions(lines: list[bytes]) -> None:
    """Reject retroactive prefix re-digest under a successor suite (n29 class)."""
    for index, line in enumerate(lines):
        row = parse_row(line)
        if not is_digest_suite_transition_event(row):
            continue
        require_known_rule_version(row, line_no=index + 1)
        claimed = _norm_hex_digest(row.get("prefix_digest"))
        if claimed is None:
            _fail(
                f"digest_suite_transition at line {index + 1} "
                "missing parseable prefix_digest"
            )
        from_suite = row.get("from_suite")
        to_suite = row.get("to_suite")
        if not isinstance(from_suite, str) or not from_suite:
            _fail(
                f"digest_suite_transition at line {index + 1} missing from_suite"
            )
        if not isinstance(to_suite, str) or not to_suite:
            _fail(
                f"digest_suite_transition at line {index + 1} missing to_suite"
            )
        auec_prefix = row.get("auec_prefix")
        if not isinstance(auec_prefix, list) or not auec_prefix:
            _fail(
                f"digest_suite_transition at line {index + 1} missing auec_prefix"
            )
        prior_digest = _auec_prefix_digest(auec_prefix, from_suite)
        successor_digest = _auec_prefix_digest(auec_prefix, to_suite)
        if claimed == successor_digest and claimed != prior_digest:
            _fail(
                f"digest_suite_transition at line {index + 1}: prefix was redigested "
                f"under successor digest suite {to_suite!r} "
                f"(binding must use {from_suite!r} digest for history written before "
                "the transition)"
            )
        if claimed != prior_digest:
            _fail(
                f"digest_suite_transition at line {index + 1}: prefix_digest does not "
                f"match digest under suite in force when prefix was written "
                f"({from_suite!r})"
            )


def verify_anchor_boundaries(lines: list[bytes]) -> None:
    interpret_anchor_lines(lines)
    verify_witness_boundary(lines)
    verify_signature_suite_boundary(lines)
    verify_digest_suite_transitions(lines)


def collect_position_bindings(lines: list[bytes]) -> list[tuple[int, dict[str, Any]]]:
    bindings: list[tuple[int, dict[str, Any]]] = []
    for index, line in enumerate(lines):
        row = parse_row(line)
        if is_position_binding_introduction_event(row):
            bindings.append((index, row))
    return bindings


def _resolve_trust_repo(
    stream_repo: str | None,
    *,
    expect_witness_repo: str | None,
    context: str,
) -> str:
    if expect_witness_repo:
        if stream_repo and stream_repo != expect_witness_repo:
            _fail(
                f"{context}: stream names repo {stream_repo!r} but "
                f"--expect-witness-repo is {expect_witness_repo!r}"
            )
        return expect_witness_repo
    if not stream_repo:
        _fail(f"{context}: missing witness repo and no --expect-witness-repo supplied")
    return stream_repo


def github_api_url(path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    return f"https://api.github.com{path}"


def fetch_github_json(url: str, *, timeout: float = 60.0) -> Any:
    """Fetch JSON from GitHub API. Any failure fails closed (no OK/PARTIAL)."""
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "aos-anchors-verify/1.0",
            "Accept": "application/vnd.github+json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        _fail(f"HTTP {exc.code} fetching {url}")
    except urllib.error.URLError as exc:
        _fail(f"network error fetching {url}: {exc.reason}")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"invalid JSON from {url}: {exc}")
    raise AssertionError("unreachable")


def resolve_default_branch(
    repo: str,
    *,
    fetch_json: Callable[[str], Any] | None = None,
) -> str:
    fetcher = fetch_json or fetch_github_json
    data = fetcher(github_api_url(f"/repos/{repo}"))
    if not isinstance(data, dict):
        _fail(f"unexpected repository metadata for {repo}")
    branch = data.get("default_branch")
    if not isinstance(branch, str) or not branch:
        _fail(f"missing default_branch for {repo}")
    return branch


def assert_commit_reachable_from_default_branch(
    repo: str,
    commit: str,
    *,
    context: str,
    commit_reachability: dict[tuple[str, str], bool] | None = None,
    fetch_json: Callable[[str], Any] | None = None,
    default_branch_cache: dict[str, str] | None = None,
) -> None:
    """Require binding commit on pin repo default-branch history (ahead_by == 0).

    Uses GET /repos/{repo}/compare/{default_branch}...{sha}.
    Do not query which branches have the SHA as tip — legitimate ancestor
    commits (e.g. 0eb69bf) are not branch heads and would be rejected.
    Unconfirmable ancestry (network, API limits, malformed responses) fails
    closed — never OK or PARTIAL.
    """
    key = (repo, commit)
    if commit_reachability is not None:
        if key not in commit_reachability:
            _fail(
                f"{context}: cannot confirm commit {commit[:12]} is reachable "
                f"from {repo} default-branch history"
            )
        if not commit_reachability[key]:
            _fail(
                f"{context}: commit {commit[:12]} is not reachable from "
                f"{repo} default-branch history (fork or non-ancestor)"
            )
        return

    fetcher = fetch_json or fetch_github_json
    if default_branch_cache is not None and repo in default_branch_cache:
        default_branch = default_branch_cache[repo]
    else:
        default_branch = resolve_default_branch(repo, fetch_json=fetcher)
        if default_branch_cache is not None:
            default_branch_cache[repo] = default_branch

    base = urllib.parse.quote(default_branch, safe="")
    head = urllib.parse.quote(commit, safe="")
    compare_url = github_api_url(f"/repos/{repo}/compare/{base}...{head}")
    data = fetcher(compare_url)
    if not isinstance(data, dict):
        _fail(f"{context}: unexpected compare response for {commit[:12]}")
    ahead_by = data.get("ahead_by")
    if not is_json_int(ahead_by):
        _fail(f"{context}: compare response missing ahead_by for {commit[:12]}")
    if ahead_by != 0:
        _fail(
            f"{context}: commit {commit[:12]} is not reachable from "
            f"{repo}@{default_branch} (ahead_by={ahead_by})"
        )


def verify_position_bindings(
    presented_lines: list[bytes],
    *,
    expect_witness_repo: str | None,
    fetch_lines: Callable[[str, str], list[bytes]] | None = None,
    witness_lines_by_ref: dict[tuple[str, str], list[bytes]] | None = None,
    commit_reachability: dict[tuple[str, str], bool] | None = None,
    fetch_json: Callable[[str], Any] | None = None,
) -> int:
    """Verify attested prefixes by byte match at named witness commits (B-1)."""
    bindings = collect_position_bindings(presented_lines)
    if not bindings:
        return 0

    max_attested = 0
    default_branch_cache: dict[str, str] = {}
    for binding_index, row in bindings:
        require_known_rule_version(row, line_no=binding_index + 1)
        attestation = row.get("attestation")
        if not isinstance(attestation, dict):
            _fail(
                f"position_binding_introduced at line {binding_index + 1} "
                "missing attestation object"
            )
        witness = attestation.get("witness")
        prefix = attestation.get("prefix")
        if not isinstance(witness, dict) or not isinstance(prefix, dict):
            _fail(
                f"position_binding_introduced at line {binding_index + 1} "
                "missing witness or prefix"
            )

        stream_repo = witness.get("repo")
        commit = witness.get("commit")
        if not isinstance(stream_repo, str) or not isinstance(commit, str):
            _fail(
                f"position_binding_introduced at line {binding_index + 1} "
                "missing repo or commit"
            )

        query_repo = _resolve_trust_repo(
            stream_repo,
            expect_witness_repo=expect_witness_repo,
            context=f"position binding at line {binding_index + 1}",
        )
        context = f"position binding at line {binding_index + 1}"
        assert_commit_reachable_from_default_branch(
            query_repo,
            commit,
            context=context,
            commit_reachability=commit_reachability,
            fetch_json=fetch_json,
            default_branch_cache=default_branch_cache,
        )

        line_count = prefix.get("line_count")
        byte_length = prefix.get("byte_length")
        expected_digest = prefix.get("sha256")
        if not is_json_int(line_count) or line_count < 1:
            _fail(
                f"position binding at line {binding_index + 1}: invalid line_count"
            )
        if not is_json_int(byte_length) or byte_length < 1:
            _fail(
                f"position binding at line {binding_index + 1}: invalid byte_length"
            )
        if not isinstance(expected_digest, str) or not expected_digest:
            _fail(f"position binding at line {binding_index + 1}: invalid sha256")

        ref = (query_repo, commit)
        if witness_lines_by_ref is not None and ref in witness_lines_by_ref:
            witness_lines = witness_lines_by_ref[ref]
        elif fetch_lines is not None:
            witness_lines = fetch_lines(query_repo, commit)
        else:
            witness_lines = fetch_repo_lines(query_repo, commit, "ANCHORS.jsonl")

        if len(witness_lines) < line_count:
            _fail(
                f"position binding at line {binding_index + 1}: witness commit "
                f"{commit[:12]} has fewer than {line_count} lines"
            )

        witness_prefix_bytes = b"".join(witness_lines[:line_count])
        if len(witness_prefix_bytes) != byte_length:
            _fail(
                f"position binding at line {binding_index + 1}: witness prefix "
                f"byte length {len(witness_prefix_bytes)} != attested {byte_length}"
            )
        if sha256_bytes(witness_prefix_bytes) != expected_digest:
            _fail(
                f"position binding at line {binding_index + 1}: witness prefix "
                "digest mismatch"
            )

        presented_prefix_bytes = b"".join(presented_lines[:line_count])
        if presented_prefix_bytes != witness_prefix_bytes:
            _fail(
                f"position binding at line {binding_index + 1}: presented prefix "
                "does not match attested witness prefix (fork or insertion detected)"
            )

        max_attested = max(max_attested, line_count)

    return max_attested


def load_line_digests(content: bytes) -> list[str]:
    try:
        data = json.loads(content.decode("utf-8"))
    except json.JSONDecodeError as exc:
        _fail(f"invalid digest sidecar JSON: {exc}")
    if not isinstance(data, dict):
        _fail("digest sidecar must be a JSON object")
    digests = data.get("line_sha256")
    if not isinstance(digests, list):
        _fail("digest sidecar missing line_sha256 list")
    return [str(item) for item in digests]


def verify_lines_against_digests(lines: list[bytes], digests: list[str]) -> None:
    """Vector 1: records-only truncation while sidecar retains prior digests."""
    if len(digests) > len(lines):
        _fail(
            "truncation vector 1: fewer anchor lines than digest sidecar "
            "(append-only violation)"
        )
    for index, expected in enumerate(digests):
        actual = sha256_line(lines[index])
        if actual != expected:
            _fail(f"digest mismatch at line {index + 1}")


def repo_from_raw_github_url(url: str) -> str | None:
    prefix = "https://raw.githubusercontent.com/"
    if not url.startswith(prefix):
        return None
    rest = url[len(prefix) :]
    parts = rest.split("/", 2)
    if len(parts) < 2:
        return None
    return f"{parts[0]}/{parts[1]}"


def raw_github_url(repo: str, ref: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/{repo}/{ref}/{path}"


def fetch_repo_lines(repo: str, ref: str, path: str) -> list[bytes]:
    url = raw_github_url(repo, ref, path)
    return bytes_to_lines(fetch_url(url))


def verify_truncation_length_only(
    presented_lines: list[bytes],
    *,
    witness_lines: list[bytes] | None,
    main_lines: list[bytes] | None,
) -> None:
    """Legacy vector 2: line-count floor only (fork-vulnerable — for self-test contrast)."""
    presented_count = len(presented_lines)
    if witness_lines is not None and len(witness_lines) > presented_count:
        _fail(
            "truncation vector 2: presented stream shorter than witness commit "
            f"({presented_count} vs {len(witness_lines)} lines)"
        )
    if main_lines is not None and len(main_lines) > presented_count:
        _fail(
            "truncation vector 2: presented stream shorter than main branch "
            f"({presented_count} vs {len(main_lines)} lines)"
        )


def verify_truncation_against_witness(
    presented_lines: list[bytes],
    *,
    witness_lines: list[bytes] | None,
    main_lines: list[bytes] | None,
    expect_witness_repo: str | None,
    max_attested_lines: int,
) -> None:
    """Vector 2 for unattested tip: length floor only when prefix not yet bound."""
    presented_count = len(presented_lines)
    if presented_count <= max_attested_lines:
        return
    if witness_lines is not None and len(witness_lines) > presented_count:
        _fail(
            "truncation vector 2: presented stream shorter than witness commit "
            f"({presented_count} vs {len(witness_lines)} lines); "
            "detection assumes witness platform history has not been rewritten"
        )
    if main_lines is not None and len(main_lines) > presented_count:
        _fail(
            "truncation vector 2: presented stream shorter than main branch "
            f"({presented_count} vs {len(main_lines)} lines); "
            "detection assumes witness platform history has not been rewritten"
        )


def format_result_summary(result: dict[str, Any]) -> str:
    return (
        f"lines={result['lines']} digests={result['digests']} "
        f"witness_repo={result['witness_repo']} "
        f"witness_commit={result['witness_commit']} "
        f"attested_prefix_lines={result['attested_prefix_lines']}"
    )


def classify_verification_outcome(
    result: dict[str, Any],
    *,
    expect_witness_repo: str | None,
    presented_lines: list[bytes] | None = None,
) -> tuple[int, str, str]:
    """Return (exit_code, stream, message) where stream is stdout or stderr."""
    summary = format_result_summary(result)
    if not expect_witness_repo:
        detail = (
            f"VERIFY UNPINNED: {summary}\n"
            "trust anchor not pinned (--expect-witness-repo omitted); "
            "verification cannot be cited as fully anchored"
        )
        return EXIT_UNPINNED, "stderr", detail
    covered = result.get("attested_unit_covered")
    if covered is None and presented_lines is not None:
        covered = attested_unit_fully_covered(
            presented_lines,
            int(result["attested_prefix_lines"]),
        )
    if covered is None:
        raise ValueError(
            "classify_verification_outcome requires attested_unit_covered "
            "in result or presented_lines"
        )
    if not covered:
        attested = result["attested_prefix_lines"]
        total = result["lines"]
        detail = (
            f"VERIFY PARTIAL: {summary}\n"
            f"attested prefix covers {attested}/{total} lines; "
            "VERIFY OK requires no anchor record rows after the attested "
            "prefix (boundary event rows alone are allowed)"
        )
        return EXIT_PARTIAL, "stderr", detail
    detail = f"VERIFY OK: {summary}"
    return EXIT_OK, "stdout", detail


def emit_trust_anchor_warning(expect_witness_repo: str | None) -> None:
    if expect_witness_repo:
        return
    print(
        "WARNING: --expect-witness-repo not set; witness repository is taken from "
        "the stream under verification. A forged stream can name an attacker "
        "repository as the trust anchor. Pinning also requires each binding "
        "commit to be reachable from that repository's default-branch history "
        "(GitHub compare ahead_by == 0); unconfirmable ancestry fails closed.",
        file=sys.stderr,
    )


def require_position_binding_attestation(max_attested: int) -> None:
    """Streams with zero attestations must not receive VERIFY OK."""
    if max_attested == 0:
        raise VerifyUnattested(
            "no position_binding_introduced attestation "
            "(attested_prefix_lines=0); digest and boundary checks alone are "
            "insufficient — offline snapshots cannot be distinguished from "
            "verified streams"
        )


def verify_from_bytes(
    anchors_content: bytes,
    digests_content: bytes,
    *,
    witness_lines: list[bytes] | None = None,
    main_lines: list[bytes] | None = None,
    check_witness_platform: bool = True,
    anchors_url: str | None = None,
    expect_witness_repo: str | None = None,
    witness_lines_by_ref: dict[tuple[str, str], list[bytes]] | None = None,
    commit_reachability: dict[tuple[str, str], bool] | None = None,
    fetch_json: Callable[[str], Any] | None = None,
) -> dict[str, Any]:
    lines = bytes_to_lines(anchors_content)
    digests = load_line_digests(digests_content)
    verify_lines_against_digests(lines, digests)
    verify_anchor_boundaries(lines)

    max_attested = 0
    if check_witness_platform:
        max_attested = verify_position_bindings(
            lines,
            expect_witness_repo=expect_witness_repo,
            witness_lines_by_ref=witness_lines_by_ref,
            commit_reachability=commit_reachability,
            fetch_json=fetch_json,
        )

    witness = load_active_witness(lines)
    if check_witness_platform:
        repo: str | None = None
        commit: str | None = None
        if witness is not None:
            repo_val = witness.get("repo")
            commit_val = witness.get("commit")
            if isinstance(repo_val, str) and isinstance(commit_val, str):
                repo, commit = repo_val, commit_val
            else:
                _fail("active witness missing repo or commit")
        elif anchors_url:
            repo = repo_from_raw_github_url(anchors_url)

        if expect_witness_repo:
            if repo and repo != expect_witness_repo:
                _fail(
                    f"stream witness repo {repo!r} != --expect-witness-repo "
                    f"{expect_witness_repo!r}"
                )
            query_repo = expect_witness_repo
        else:
            query_repo = repo

        if query_repo or witness_lines is not None or main_lines is not None:
            if witness_lines is None and query_repo and commit:
                witness_lines = fetch_repo_lines(query_repo, commit, "ANCHORS.jsonl")
            if main_lines is None and query_repo:
                main_lines = fetch_repo_lines(query_repo, "main", "ANCHORS.jsonl")
            verify_truncation_against_witness(
                lines,
                witness_lines=witness_lines,
                main_lines=main_lines,
                expect_witness_repo=expect_witness_repo,
                max_attested_lines=max_attested,
            )
        require_position_binding_attestation(max_attested)

    unit_covered = (
        attested_unit_fully_covered(lines, max_attested) if max_attested > 0 else False
    )
    return {
        "lines": len(lines),
        "digests": len(digests),
        "witness_repo": witness.get("repo") if witness else None,
        "witness_commit": witness.get("commit") if witness else None,
        "attested_prefix_lines": max_attested,
        "attested_unit_covered": unit_covered,
    }


def verify_urls(
    anchors_url: str,
    digests_url: str,
    *,
    expect_witness_repo: str | None = None,
) -> dict[str, Any]:
    anchors_content = fetch_url(anchors_url)
    digests_content = fetch_url(digests_url)
    return verify_from_bytes(
        anchors_content,
        digests_content,
        check_witness_platform=True,
        anchors_url=anchors_url,
        expect_witness_repo=expect_witness_repo,
    )


def _jsonl_bytes(obj: dict[str, Any]) -> bytes:
    return (json.dumps(obj, ensure_ascii=True, separators=(",", ":")) + "\n").encode("utf-8")


def _build_fork_self_test_streams(
    live_lines: list[bytes] | None = None,
) -> tuple[list[bytes], list[bytes], dict[str, Any], list[bytes], bytes]:
    """wowlegend-class fork derived from live stream when available."""
    if live_lines is not None and len(live_lines) >= 19:
        shared = live_lines[:16]
        witness_real = live_lines[16]
        suite_event = live_lines[17]
        binding_line = live_lines[18]
        tail = live_lines[19:]
        witness_row = parse_row(witness_real)
        forged_at = str(witness_row.get("introduced_at") or "2026-08-07") + "-forged"
        witness_row["introduced_at"] = forged_at
        witness_fake = _jsonl_bytes(witness_row)
        attestation = parse_row(binding_line)["attestation"]
        if not isinstance(attestation, dict):
            _fail("live position_binding row missing attestation for fork self-test")
        f18a = shared + [witness_real, suite_event]
        f18b = shared + [witness_fake, suite_event]
        return f18a, f18b, attestation, tail, binding_line

    shared = [
        _jsonl_bytes(
            {
                "date": "2099-W01",
                "asset_id": "demo-a",
                "sha256": "aa",
                "size_bytes": 1,
                "note": "",
            }
        ),
        _jsonl_bytes(
            {
                "date": "2099-W01",
                "asset_id": "demo-b",
                "sha256": "bb",
                "size_bytes": 1,
                "note": "",
            }
        ),
    ]
    while len(shared) < 16:
        idx = len(shared)
        shared.append(
            _jsonl_bytes(
                {
                    "date": "2099-W01",
                    "asset_id": f"demo-{idx}",
                    "sha256": f"{idx:02x}",
                    "size_bytes": 1,
                    "note": "",
                }
            )
        )

    prior_head = "0eb69bf9f26f03b8d4fbce3b3b64ac46e10e1582"
    witness_real = _jsonl_bytes(
        {
            "event": "witness_ref_introduced",
            "rule_version": "witness-ref-v1",
            "witness": {
                "kind": "public_vcs",
                "repo": "aos-standard/catalog",
                "commit": prior_head,
            },
            "introduced_at": "2026-08-07",
        }
    )
    witness_fake = _jsonl_bytes(
        {
            "event": "witness_ref_introduced",
            "rule_version": "witness-ref-v1",
            "witness": {
                "kind": "public_vcs",
                "repo": "aos-standard/catalog",
                "commit": prior_head,
            },
            "introduced_at": "2026-08-07-forged",
        }
    )
    suite_event = _jsonl_bytes(
        {
            "event": "signature_suite_introduced",
            "rule_version": "signature-suite-v1",
            "signature_suite": "none",
            "introduced_at": "2026-08-08",
        }
    )

    f18a = shared + [witness_real, suite_event]
    f18b = shared + [witness_fake, suite_event]

    prefix_bytes = b"".join(f18a)
    attestation = {
        "witness": {
            "kind": "public_vcs",
            "repo": "aos-standard/catalog",
            "commit": "realwitness00000000000000000000000000000001",
        },
        "prefix": {
            "line_count": len(f18a),
            "byte_length": len(prefix_bytes),
            "sha256": sha256_bytes(prefix_bytes),
        },
    }
    return f18a, f18b, attestation, [], _jsonl_bytes(
        {
            "event": POSITION_BINDING_EVENT_NAME,
            "rule_version": "position-binding-v1",
            "attestation": attestation,
            "introduced_at": "2026-08-09",
        }
    )


def _load_live_anchors_lines_for_self_test() -> list[bytes] | None:
    live_path = Path(__file__).resolve().parent / "ANCHORS.jsonl"
    if not live_path.is_file():
        return None
    return bytes_to_lines(live_path.read_bytes())


def _rejection_class(exc: BaseException) -> str:
    message = str(exc)
    if "digest mismatch" in message:
        return "digest_mismatch"
    if "fork or insertion detected" in message:
        return "fork"
    if "not reachable from" in message or "cannot confirm commit" in message:
        return "unreachable_witness"
    if "truncation vector" in message:
        return "truncation"
    if isinstance(exc, VerifyUnattested):
        return "unattested"
    if "prefix was redigested" in message:
        return "suite_transition_redigest"
    return "verify_error"


def run_self_test() -> int:
    """Adversarial vectors must fail closed; valid minimal stream must pass."""
    cases_failed = 0

    def expect_fail(label: str, fn) -> None:
        nonlocal cases_failed
        try:
            fn()
        except VerifyError:
            print(f"PASS self-test: {label} (fail closed)", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001
            print(f"FAIL self-test: {label} unexpected {exc!r}", file=sys.stderr)
            cases_failed += 1
        else:
            print(f"FAIL self-test: {label} did not fail closed", file=sys.stderr)
            cases_failed += 1

    def expect_unattested(label: str, fn) -> None:
        nonlocal cases_failed
        try:
            fn()
        except VerifyUnattested:
            print(f"PASS self-test: {label} (verify unattested)", file=sys.stderr)
        except VerifyError as exc:
            print(
                f"FAIL self-test: {label} raised VerifyError instead of "
                f"VerifyUnattested ({exc})",
                file=sys.stderr,
            )
            cases_failed += 1
        except Exception as exc:  # noqa: BLE001
            print(f"FAIL self-test: {label} unexpected {exc!r}", file=sys.stderr)
            cases_failed += 1
        else:
            print(f"FAIL self-test: {label} did not report unattested", file=sys.stderr)
            cases_failed += 1

    line_a = _jsonl_bytes(
        {
            "date": "2099-W01",
            "asset_id": "demo-a",
            "sha256": "aa",
            "size_bytes": 1,
            "note": "",
        }
    )
    line_b = _jsonl_bytes(
        {
            "date": "2099-W01",
            "asset_id": "demo-b",
            "sha256": "bb",
            "size_bytes": 1,
            "note": "",
        }
    )
    witness_event = _jsonl_bytes(
        {
            "event": "witness_ref_introduced",
            "rule_version": "witness-ref-v1",
            "witness": {
                "kind": "public_vcs",
                "repo": "example/catalog",
                "commit": "abc123",
            },
            "introduced_at": "2099-01-01",
        }
    )
    suite_event = _jsonl_bytes(
        {
            "event": "signature_suite_introduced",
            "rule_version": "signature-suite-v1",
            "signature_suite": "none",
            "introduced_at": "2099-01-02",
        }
    )
    line_c = _jsonl_bytes(
        {
            "date": "2099-W02",
            "asset_id": "demo-c",
            "sha256": "cc",
            "size_bytes": 1,
            "note": "",
            "witness": {
                "kind": "public_vcs",
                "repo": "example/catalog",
                "commit": "abc123",
            },
            "signature_suite": "none",
        }
    )

    full_lines = [line_a, line_b, witness_event, suite_event, line_c]
    full_digests = [sha256_line(line) for line in full_lines]

    expect_fail(
        "vector 1 records-only truncation",
        lambda: verify_lines_against_digests(full_lines[:2], full_digests),
    )

    truncated = full_lines[:4]
    truncated_digests = [sha256_line(line) for line in truncated]
    long_witness = full_lines + [line_c]

    expect_fail(
        "vector 2 both truncated vs witness reference",
        lambda: verify_truncation_against_witness(
            truncated,
            witness_lines=long_witness,
            main_lines=long_witness,
            expect_witness_repo="example/catalog",
            max_attested_lines=0,
        ),
    )

    try:
        verify_from_bytes(
            b"".join(truncated),
            json.dumps({"version": "1.0.0", "line_sha256": truncated_digests}).encode(
                "utf-8"
            ),
            witness_lines=long_witness,
            main_lines=long_witness,
            check_witness_platform=True,
            expect_witness_repo="example/catalog",
        )
    except VerifyError:
        print("PASS self-test: vector 2 end-to-end (fail closed)", file=sys.stderr)
    else:
        print("FAIL self-test: vector 2 end-to-end did not fail closed", file=sys.stderr)
        cases_failed += 1

    expect_unattested(
        "stream without position binding is unattested not ok",
        lambda: verify_from_bytes(
            b"".join(full_lines),
            json.dumps({"version": "1.0.0", "line_sha256": full_digests}).encode(
                "utf-8"
            ),
            witness_lines=full_lines,
            main_lines=full_lines,
            check_witness_platform=True,
            expect_witness_repo="example/catalog",
        ),
    )

    live_lines = _load_live_anchors_lines_for_self_test()
    f18a, f18b, attestation, tail, binding_line = _build_fork_self_test_streams(live_lines)
    witness_ref = attestation["witness"]
    repo = witness_ref["repo"]
    commit = witness_ref["commit"]
    witness_map = {(repo, commit): f18a}
    reachability_ok = {(repo, commit): True}
    reference_main = live_lines if live_lines is not None else f18a

    try:
        verify_truncation_length_only(f18a, witness_lines=f18a, main_lines=f18a)
        verify_truncation_length_only(f18b, witness_lines=f18a, main_lines=f18a)
        print(
            "PASS self-test: fork vector length-only accepts both f18a and f18b",
            file=sys.stderr,
        )
    except VerifyError as exc:
        print(f"FAIL self-test: fork length-only baseline ({exc})", file=sys.stderr)
        cases_failed += 1

    f18a_bound = f18a + [binding_line] + tail
    f18b_bound = f18b + [binding_line] + tail
    f18a_digests = [sha256_line(line) for line in f18a_bound]
    f18b_digests = [sha256_line(line) for line in f18b_bound]

    try:
        verify_from_bytes(
            b"".join(f18a_bound),
            json.dumps({"version": "1.0.0", "line_sha256": f18a_digests}).encode(
                "utf-8"
            ),
            witness_lines=reference_main,
            main_lines=reference_main,
            check_witness_platform=True,
            expect_witness_repo=repo,
            witness_lines_by_ref=witness_map,
            commit_reachability=reachability_ok,
        )
        print("PASS self-test: fork vector f18a accepted with position binding", file=sys.stderr)
    except VerifyUnattested as exc:
        print(
            f"FAIL self-test: fork f18a unattested "
            f"(rejection={_rejection_class(exc)}: {exc})",
            file=sys.stderr,
        )
        cases_failed += 1
    except VerifyError as exc:
        print(
            f"FAIL self-test: fork f18a rejected "
            f"(rejection={_rejection_class(exc)}: {exc})",
            file=sys.stderr,
        )
        cases_failed += 1

    def _expect_fork_reject_f18b() -> None:
        try:
            verify_from_bytes(
                b"".join(f18b_bound),
                json.dumps({"version": "1.0.0", "line_sha256": f18b_digests}).encode(
                    "utf-8"
                ),
                witness_lines=reference_main,
                main_lines=reference_main,
                check_witness_platform=True,
                expect_witness_repo=repo,
                witness_lines_by_ref=witness_map,
                commit_reachability=reachability_ok,
            )
        except VerifyError as exc:
            rejection = _rejection_class(exc)
            if rejection != "fork":
                raise VerifyError(
                    f"expected fork rejection for f18b, got {rejection}: {exc}"
                ) from exc
            print(
                f"PASS self-test: fork vector f18b rejected "
                f"(rejection={rejection})",
                file=sys.stderr,
            )
            return
        raise AssertionError("f18b bound stream did not fail closed")

    try:
        _expect_fork_reject_f18b()
    except (VerifyError, AssertionError) as exc:
        print(f"FAIL self-test: fork vector f18b ({exc})", file=sys.stderr)
        cases_failed += 1

    forge18_digests = [sha256_line(line) for line in f18b]
    expect_unattested(
        "forge18 downgrade without attestation",
        lambda: verify_from_bytes(
            b"".join(f18b),
            json.dumps({"version": "1.0.0", "line_sha256": forge18_digests}).encode(
                "utf-8"
            ),
            witness_lines=f18a,
            main_lines=f18a,
            check_witness_platform=True,
            expect_witness_repo=repo,
        ),
    )

    expect_fail(
        "expect-witness-repo mismatch fail closed",
        lambda: verify_position_bindings(
            f18a_bound,
            expect_witness_repo="trusted/catalog",
            witness_lines_by_ref=witness_map,
            commit_reachability=reachability_ok,
        ),
    )

    expect_fail(
        "fork-derived binding commit fail closed",
        lambda: verify_position_bindings(
            f18a_bound,
            expect_witness_repo=repo,
            witness_lines_by_ref=witness_map,
            commit_reachability={(repo, commit): False},
        ),
    )

    expect_fail(
        "unconfirmable ancestry fail closed",
        lambda: verify_position_bindings(
            f18a_bound,
            expect_witness_repo=repo,
            witness_lines_by_ref=witness_map,
            commit_reachability={},
        ),
    )

    ancestor_commit = "0eb69bf9f26f03b8d4fbce3b3b64ac46e10e1582"

    def _fake_compare(url: str) -> Any:
        if url.endswith("/repos/aos-standard/catalog"):
            return {"default_branch": "main"}
        if "compare/" in url and ancestor_commit in url:
            return {"ahead_by": 0, "behind_by": 14, "status": "behind"}
        _fail(f"unexpected fetch_json url in self-test: {url}")

    try:
        assert_commit_reachable_from_default_branch(
            "aos-standard/catalog",
            ancestor_commit,
            context="self-test ancestor",
            fetch_json=_fake_compare,
        )
        print(
            "PASS self-test: ancestor commit 0eb69bf ahead_by==0 accepted",
            file=sys.stderr,
        )
    except VerifyError as exc:
        print(f"FAIL self-test: ancestor 0eb69bf rejected ({exc})", file=sys.stderr)
        cases_failed += 1

    with warnings.catch_warnings(record=True):
        emit_trust_anchor_warning(None)
    print("PASS self-test: missing expect-witness-repo emits warning", file=sys.stderr)

    hybrid_row = parse_row(witness_event)
    hybrid_row["asset_id"] = "demo-a"
    expect_fail(
        "hybrid event+asset_id fail closed",
        lambda: interpret_anchor_row(hybrid_row, line_no=1),
    )
    unknown_version_row = parse_row(witness_event)
    unknown_version_row["rule_version"] = "witness-ref-v99"
    expect_fail(
        "unknown rule_version fail closed",
        lambda: interpret_anchor_row(unknown_version_row, line_no=1),
    )
    binding_event = _jsonl_bytes(
        {
            "event": POSITION_BINDING_EVENT_NAME,
            "rule_version": KNOWN_BOUNDARY_RULE_VERSIONS[POSITION_BINDING_EVENT_NAME],
            "attestation": {
                "witness": {
                    "kind": "public_vcs",
                    "repo": "example/catalog",
                    "commit": "abc123",
                },
                "prefix": {"line_count": 1, "byte_length": 1, "sha256": "aa"},
            },
            "introduced_at": "2099-01-03",
        }
    )
    try:
        interpret_anchor_row(parse_row(witness_event), line_no=1)
        interpret_anchor_row(parse_row(suite_event), line_no=2)
        interpret_anchor_row(parse_row(binding_event), line_no=3)
        print(
            "PASS self-test: known boundary events and rule_versions interpret",
            file=sys.stderr,
        )
    except VerifyError as exc:
        print(
            f"FAIL self-test: known boundary interpret ({exc})",
            file=sys.stderr,
        )
        cases_failed += 1

    return 1 if cases_failed else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify ANCHORS.jsonl and digest sidecar from public URLs. "
            "Stdlib only. Does not verify signatures. "
            "Attested-prefix fork detection only; see --help limits."
        ),
    )
    parser.add_argument(
        "--anchors-url",
        help="HTTPS URL to ANCHORS.jsonl (e.g. raw.githubusercontent.com/.../ANCHORS.jsonl)",
    )
    parser.add_argument(
        "--digests-url",
        help="HTTPS URL to ANCHORS.jsonl.digests.json",
    )
    parser.add_argument(
        "--expect-witness-repo",
        help=(
            "Trust anchor: owner/repo for witness platform queries (strongly recommended). "
            "Must match stream witness repo. Binding commits must be reachable from this "
            "repository's default-branch history (GitHub compare ahead_by == 0). "
            "Unconfirmable ancestry fails closed."
        ),
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run built-in adversarial vectors (no network)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_test()

    if not args.anchors_url or not args.digests_url:
        parser.error("--anchors-url and --digests-url are required unless --self-test")

    emit_trust_anchor_warning(args.expect_witness_repo)

    try:
        result = verify_urls(
            args.anchors_url,
            args.digests_url,
            expect_witness_repo=args.expect_witness_repo,
        )
    except VerifyUnattested as exc:
        print(f"VERIFY UNATTESTED: {exc}", file=sys.stderr)
        print(LIMITATIONS_TEXT, file=sys.stderr)
        return EXIT_UNATTESTED
    except VerifyError as exc:
        print(f"VERIFY FAILED: {exc}", file=sys.stderr)
        print(LIMITATIONS_TEXT, file=sys.stderr)
        return EXIT_FAILED

    summary = format_result_summary(result)

    exit_code, stream, message = classify_verification_outcome(
        result,
        expect_witness_repo=args.expect_witness_repo,
    )
    if stream == "stdout":
        print(message)
    else:
        print(message, file=sys.stderr)
    print(LIMITATIONS_TEXT, file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
