"""Only explicit unreferenced staging can leave the active evidence namespace."""

import pytest
from sqlalchemy.orm import sessionmaker

from smithguard.evidence import EvidenceIntegrityError, LocalImmutableEvidenceStore
from smithguard.evidence_quarantine import EvidenceQuarantineError, quarantine_orphan_stages
from tests.test_evidence_finalization import _register


def setup(tmp_path, database):
    store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    parent = tmp_path / "quarantine"
    parent.mkdir(mode=0o700)
    return store, dict(
        factory=sessionmaker(database.engine),
        store=store,
        parent=parent,
        operation_id="20260924-" + "b" * 32,
        verify_quiescence=lambda: None,
    )


@pytest.mark.parametrize(
    "fault", ["size", "extra", "changed", "symlink", "hardlink", "world", "busy"]
)
def test_ambiguous_stage_refused_without_loss(database, tmp_path, fault):
    store, arguments = setup(tmp_path, database)
    stage = store.stage_bytes(b"synthetic orphan")
    path = store.root / ".staging/sha256" / stage.digest[7:9] / stage.digest[7:]
    approved = {stage.digest: stage.byte_count}
    if fault == "size":
        approved[stage.digest] += 1
    elif fault == "extra":
        store.stage_bytes(b"unapproved")
    elif fault == "changed":
        path.chmod(0o600)
        path.write_bytes(b"changed")
        path.chmod(0o400)
    elif fault == "symlink":
        retained = tmp_path / "retained"
        path.rename(retained)
        path.symlink_to(retained)
    elif fault == "hardlink":
        (tmp_path / "retained").hardlink_to(path)
    elif fault == "world":
        path.chmod(0o444)
    else:

        def busy():
            raise EvidenceQuarantineError("synthetic producer active")

        arguments["verify_quiescence"] = busy
    with pytest.raises((EvidenceQuarantineError, EvidenceIntegrityError)):
        quarantine_orphan_stages(**arguments, approved=approved)
    assert path.exists()
    store.close()


def test_committed_finalization_is_reconciled_and_cannot_be_quarantined(database, tmp_path):
    from tests.test_evidence_finalization import FailOnceEvidenceStore

    store, arguments = setup(tmp_path, database)
    wrapper = FailOnceEvidenceStore(store)
    with arguments["factory"]() as session, session.begin():
        stage = _register(session, store=wrapper, body=b"committed pending finalization")
    assert store.pending_manifest()
    with pytest.raises(EvidenceQuarantineError, match="allowlist"):
        quarantine_orphan_stages(**arguments, approved={stage.digest: stage.byte_count})
    assert store.read_bytes(stage.digest) == b"committed pending finalization"
    assert store.pending_manifest() == []
    assert (arguments["parent"] / arguments["operation_id"] / "failure.json").exists()
    with pytest.raises(FileExistsError):
        quarantine_orphan_stages(**arguments, approved={stage.digest: stage.byte_count})
    store.close()


def test_finalized_reference_blocks_duplicate_stage_quarantine(database, tmp_path):
    store, arguments = setup(tmp_path, database)
    with arguments["factory"]() as session, session.begin():
        stage = _register(session, store=store, body=b"already finalized")
    duplicate = store.stage_bytes(b"already finalized")
    with pytest.raises(EvidenceQuarantineError, match="referenced"):
        quarantine_orphan_stages(**arguments, approved={duplicate.digest: duplicate.byte_count})
    assert store.pending_manifest()[0].digest == stage.digest
    assert store.read_bytes(stage.digest) == b"already finalized"
    store.close()
