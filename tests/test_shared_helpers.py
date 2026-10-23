"""The shared helper homes reproduce the copies they replace, byte for byte."""

from __future__ import annotations

import errno
import json
import os
import stat
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from smithguard import ecosystems, fsio, identifiers, xai_settings
from smithguard.contracts.generated import Ecosystem
from smithguard.db.locks import advisory_xact_lock

ROOT = Path(__file__).resolve().parents[1]
CORPUS = [
    *sorted((ROOT / "contracts" / "v1").glob("*.json")),
    ROOT / "src" / "smithguard" / "generated_artifacts" / "manifest.json",
    ROOT / "migrations" / "journal.json",
]
SYNTHETIC = {
    "z": [1, 2.5, "caf\u00e9", {"nested": {"deep": [None, True]}}, []],
    "a": 10**20,
    "m": {"k": "v", "j": ""},
}


def _documents() -> list[object]:
    return [json.loads(path.read_text(encoding="utf-8")) for path in CORPUS] + [SYNTHETIC]


def test_canonical_encoders_match_the_inline_expressions_they_replace() -> None:
    for document in _documents():
        compact = json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
        assert identifiers.canonical_json_bytes(document) == compact
        assert identifiers.canonical_json_line(document) == compact + b"\n"
        pretty = (
            json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)
            + "\n"
        ).encode("ascii")
        assert identifiers.pretty_json_bytes(document) == pretty


def test_committed_journal_and_manifest_are_pretty_layout_bytes() -> None:
    for path in (
        ROOT / "migrations" / "journal.json",
        ROOT / "src" / "smithguard" / "generated_artifacts" / "manifest.json",
    ):
        body = path.read_bytes()
        assert identifiers.pretty_json_bytes(json.loads(body)) == body, path


def test_timestamp_and_stable_id_pins() -> None:
    value = datetime(2026, 9, 18, 5, 39, 7, 123456, tzinfo=UTC)
    assert identifiers.timestamp(value) == "2026-09-18T05:39:07Z"
    assert (
        identifiers.stable_id("pin", "a", {"b": 1})
        == "gbsec:pin:6e097e39225dd5c9976cab6d5889b22bb4357cf3"
    )
    assert identifiers.sha256_id(b"x").startswith("sha256:")


def test_parse_timestamp_and_require_aware_utc_match_the_old_local_copies() -> None:
    parsed = identifiers.parse_timestamp("2026-09-18T05:39:07Z")
    assert parsed == datetime(2026, 9, 18, 5, 39, 7, tzinfo=UTC)
    offset = identifiers.parse_timestamp("2026-09-18T07:39:07+02:00")
    assert offset == parsed and offset.tzinfo is UTC
    for bad in ("", "2026-09-18T05:39:07", "not-a-time", 5, "x" * 65):
        with pytest.raises(ValueError):
            identifiers.parse_timestamp(bad)
    with pytest.raises(ValueError):
        identifiers.parse_timestamp("2026-09-18T05:39:07Z", maximum=10)
    assert identifiers.require_aware_utc(
        datetime(2026, 1, 1, 1, tzinfo=timezone(timedelta(hours=1)))
    ) == datetime(2026, 1, 1, 0, tzinfo=UTC)
    with pytest.raises(ValueError):
        identifiers.require_aware_utc(datetime(2026, 1, 1))


def test_strict_json_loads_rejects_duplicates_constants_size_and_depth() -> None:
    assert identifiers.strict_json_loads(b'{"a": [1, 2], "b": {"c": null}}') == {
        "a": [1, 2],
        "b": {"c": None},
    }
    with pytest.raises(identifiers.DuplicateJsonKeyError):
        identifiers.strict_json_loads('{"a": 1, "a": 2}')
    for body in ("NaN", "[Infinity]", "{", ""):
        with pytest.raises(ValueError):
            identifiers.strict_json_loads(body)
    with pytest.raises(ValueError, match="too many nodes"):
        identifiers.strict_json_loads("[" + ",".join(["1"] * 30) + "]", max_nodes=10)
    with pytest.raises(ValueError, match="nested too deeply"):
        identifiers.strict_json_loads("[" * 40 + "]" * 40, max_depth=32)
    seen: list[int] = []
    identifiers.strict_json_loads("[1, [2, 3]]", on_node=lambda: seen.append(1), node_stride=1)
    assert len(seen) == 5
    strided: list[int] = []
    identifiers.strict_json_loads(
        "[" + ",".join("1" for _ in range(300)) + "]", on_node=lambda: strided.append(1)
    )
    assert len(strided) == 2


def test_shared_patterns_hold_the_exact_frozen_text() -> None:
    assert identifiers.STABLE_ID.pattern == r"^gbsec:[a-z0-9][a-z0-9:._/-]+$"
    assert identifiers.SHA256.pattern == r"^sha256:[a-f0-9]{64}$"
    assert identifiers.SHA256_HEX.pattern == r"^[a-f0-9]{64}$"
    assert identifiers.SHA1_HEX.pattern == r"^[a-f0-9]{40}$"
    assert identifiers.SHARD.pattern == r"^[a-f0-9]{2}$"
    assert identifiers.CWE_ID.pattern == r"^CWE-[1-9][0-9]{0,5}$"
    assert identifiers.ACTOR_ID.pattern == r"^[A-Za-z0-9][A-Za-z0-9:._/-]{2,159}$"
    assert identifiers.REASON_CODE_LONG.pattern == r"^[a-z0-9][a-z0-9_]{1,119}$"
    assert identifiers.REASON_CODE_SHORT.pattern == r"^[a-z0-9][a-z0-9_]{1,79}$"


def test_ecosystem_vocabulary_is_frozen_to_the_generated_enum() -> None:
    generated = {member.value for member in Ecosystem} - {"unknown"}
    assert set(ecosystems.CANONICAL_ECOSYSTEMS) == generated
    assert len(set(ecosystems.CANONICAL_ECOSYSTEMS)) == 17
    assert set(ecosystems.CANONICAL_ECOSYSTEMS) > ecosystems.THREAT_SEARCH_ECOSYSTEMS
    assert set(ecosystems.REGISTRY_HOSTS_BY_ECOSYSTEM) == set(ecosystems.CANONICAL_ECOSYSTEMS)
    assert set(ecosystems.PURL_TYPE_BY_ECOSYSTEM) == set(ecosystems.CANONICAL_ECOSYSTEMS) - {
        "npm",
        "pypi",
        "github-actions",
        "oci",
        "docker",
    }
    with pytest.raises(TypeError):
        ecosystems.PURL_TYPE_BY_ECOSYSTEM["npm"] = "npm"  # type: ignore[index]


def test_xai_settings_hold_one_spelling_of_each_bound() -> None:
    assert xai_settings.XAI_MAX_REQUEST_BYTES == 64 * 1024
    assert xai_settings.XAI_MAX_RESPONSE_BYTES == 1024 * 1024
    assert xai_settings.XAI_RECHECK_MAX_TOTAL_TOKENS == 1_508_192
    assert xai_settings.XAI_RECHECK_MAX_TOTAL_TOKENS == (
        xai_settings.XAI_RECHECK_MAX_INPUT_TOKENS + xai_settings.XAI_RECHECK_MAX_OUTPUT_TOKENS
    )
    assert xai_settings.XAI_RESPONSES_ENDPOINT == "https://api.x.ai/v1/responses"
    # Retained policy3/4/5 and legacy recheck keep their historical bounds.
    assert {
        xai_settings.XAI_QUALIFICATION_MAX_OUTPUT_TOKENS,
        xai_settings.XAI_RECHECK_MAX_OUTPUT_TOKENS,
        xai_settings.XAI_MAX_OUTPUT_TOKENS_PER_REQUEST,
        xai_settings.XAI_DISCOVERY_STAGE_MAX_OUTPUT_TOKENS,
    } == {8_192}
    assert xai_settings.XAI_DISCOVERY_DEFAULT_MAX_OUTPUT_TOKENS is None
    assert xai_settings.XAI_DISCOVERY_DEFAULT_MAX_TOTAL_TOKENS is None


def test_advisory_lock_helper_takes_the_transaction_lock(database) -> None:
    with Session(database.engine) as session, session.begin():
        advisory_xact_lock(session, "helper:lock")
        held = session.scalar(
            text(
                "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' "
                "AND pid = pg_backend_pid() AND objid = "
                "(hashtextextended('helper:lock', 0) & x'FFFFFFFF'::bigint)::int"
            )
        )
        assert held == 1
        advisory_xact_lock(session, "helper:lock")  # same transaction: a no-op


def test_fsio_writes_and_reads_privately(tmp_path: Path) -> None:
    target = tmp_path / "receipt.json"
    fsio.atomic_write(target, b"one", mode=0o640)
    assert target.read_bytes() == b"one"
    assert stat.S_IMODE(target.stat().st_mode) == 0o640
    assert not list(tmp_path.glob(".receipt.json.*"))
    fsio.atomic_write(target, b"two", mode=0o600, random_suffix=False)
    assert target.read_bytes() == b"two"
    assert fsio.read_private_file(target, maximum=16) == b"two"
    with pytest.raises(fsio.FsioError, match="invalid size"):
        fsio.read_private_file(target, maximum=1)
    with pytest.raises(fsio.FsioError, match="required mode"):
        fsio.read_private_file(target, maximum=16, exact_mode=0o640)
    target.chmod(0o644)
    with pytest.raises(fsio.FsioError, match="excess permissions"):
        fsio.read_private_file(target, maximum=16)
    assert fsio.read_private_file(target, maximum=16, mode_mask=None) == b"two"
    with pytest.raises(fsio.FsioError, match="wrong owner"):
        fsio.read_private_file(target, maximum=16, mode_mask=None, uid=os.getuid() + 1)
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(fsio.FsioError, match="opened safely") as symlink_failure:
        fsio.read_private_file(link, maximum=16, mode_mask=None)
    assert symlink_failure.value.code == "unsafe"
    assert symlink_failure.value.errno == errno.ELOOP
    with pytest.raises(fsio.FsioError, match="missing"):
        fsio.read_private_file(tmp_path / "absent", maximum=16)
    with pytest.raises(FileExistsError):
        fsio.write_exclusive(target, b"three")
    fsio.fsync_directory(tmp_path)
    fsio.fsync_directory(tmp_path, nofollow=True)


def test_strict_json_and_timestamp_errors_carry_typed_reasons(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases = {
        "{": "invalid",
        '{"a":1,"a":2}': "duplicate_key",
        "NaN": "non_finite",
        "[" * 40 + "]" * 40: "too_deep",
        "[" + ",".join("1" for _ in range(60)) + "]": "too_many_nodes",
    }
    for body, reason in cases.items():
        with pytest.raises(identifiers.StrictJsonError) as caught:
            identifiers.strict_json_loads(body, max_nodes=50, max_depth=32)
        assert caught.value.reason == reason
        if reason == "invalid":
            assert isinstance(caught.value.__cause__, json.JSONDecodeError)
    assert issubclass(identifiers.DuplicateJsonKeyError, identifiers.StrictJsonError)
    assert identifiers.strict_json_loads('{"a": 1}'.encode("utf-16")) == {"a": 1}
    # Bytes parity with json.loads: lone surrogates pass, invalid UTF-8 and runaway
    # nesting raise the same exception classes json.loads raised.
    surrogate = b'"\xed\xa0\x80"'
    assert identifiers.strict_json_loads(surrogate) == json.loads(surrogate)
    with pytest.raises(UnicodeDecodeError):
        identifiers.strict_json_loads(b'"\xff"')
    # Native parser recursion limits vary across Python builds and runner stacks.
    # Check propagation deterministically; real depth/node bounds are tested above.
    recursion_error = RecursionError("synthetic parser recursion limit")

    def exhausted_parser(*args, **kwargs):
        raise recursion_error

    with monkeypatch.context() as patch:
        patch.setattr(identifiers.json, "loads", exhausted_parser)
        with pytest.raises(RecursionError) as recursion_failure:
            identifiers.strict_json_loads("[]")
        assert recursion_failure.value is recursion_error
    assert identifiers.REGISTER_JSON_MAX_NODES == 200_000
    assert identifiers.REGISTER_JSON_MAX_DEPTH == 32
    for value, reason in (
        ("x" * 65, "bounded"),
        ("", "bounded"),
        (7, "bounded"),
        ("2026-13-01T00:00:00Z", "format"),
        ("2026-09-18T05:39:07", "naive"),
    ):
        with pytest.raises(identifiers.TimestampError) as failure:
            identifiers.parse_timestamp(value)
        assert failure.value.reason == reason


def test_fsio_modes_survive_a_restrictive_umask(tmp_path: Path) -> None:
    previous = os.umask(0o077)
    try:
        exclusive = tmp_path / "exclusive.json"
        fsio.write_exclusive(exclusive, b"one", mode=0o640)
        assert stat.S_IMODE(exclusive.stat().st_mode) == 0o640
        replaced = tmp_path / "replaced.json"
        fsio.atomic_write(replaced, b"two", mode=0o640)
        assert stat.S_IMODE(replaced.stat().st_mode) == 0o640
        fsio.atomic_write(replaced, b"three", mode=0o644, random_suffix=False)
        assert stat.S_IMODE(replaced.stat().st_mode) == 0o644
    finally:
        os.umask(previous)


def test_write_exclusive_removes_a_partial_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing_fsync(descriptor: int) -> None:
        raise OSError("disk detached")

    monkeypatch.setattr(fsio.os, "fsync", failing_fsync)
    removed = tmp_path / "removed.json"
    with pytest.raises(OSError, match="disk detached"):
        fsio.write_exclusive(removed, b"partial")
    assert not removed.exists()
    # The writers that must keep a partial file (deploy markers, host-run tools) inline
    # their own exclusive create; the shared helper always removes one.


def test_read_private_file_refuses_a_fifo_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(fsio.FsioError) as failure:
        fsio.read_private_file(fifo, maximum=16)
    assert failure.value.code == "not_regular"


def test_write_exclusive_cleanup_tolerates_an_unremovable_partial_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing_fsync(descriptor: int) -> None:
        raise OSError("disk detached")

    monkeypatch.setattr(fsio.os, "fsync", failing_fsync)
    original_unlink = Path.unlink

    def refusing_unlink(self: Path, *args: object, **kwargs: object) -> None:
        raise PermissionError("unlink refused")

    monkeypatch.setattr(Path, "unlink", refusing_unlink)
    with pytest.raises(OSError, match="disk detached"):
        fsio.write_exclusive(tmp_path / "stuck.json", b"partial")
    monkeypatch.setattr(Path, "unlink", original_unlink)
