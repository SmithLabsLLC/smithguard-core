"""Network-free bulletin status and explicit operator publication commands."""

from __future__ import annotations

import argparse
import json
import os
import pwd
import re
import threading
import uuid
from contextlib import contextmanager
from datetime import UTC, date, datetime
from pathlib import Path

import psycopg
from sqlalchemy import cast, create_engine, func, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from smithguard import bulletin_store as store
from smithguard.bulletin_contract import BulletinError, content_id, validate_content
from smithguard.bulletin_policy import read_grant
from smithguard.db.bulletin_models import BulletinCurrent, BulletinPublicVersion, BulletinRevision
from smithguard.identifiers import canonical_json_bytes, sha256_id, strict_json_loads, timestamp
from smithguard.official_notice_runtime import rights_registry_path, running_release
from smithguard.runtime import _secure_file, _validate_database_url
from smithguard.source_rights import RightsRegistry, SourceRightsError


def current_grant(*, now):
    return read_grant(release=running_release(), registry_path=rights_registry_path(), now=now)


def operator_connection():
    """Authenticate the root CLI as the existing local maintenance role.

    The process retains its root-owned deployment lock and restores its effective
    identity before SQLAlchemy uses the connection. PostgreSQL peer authentication
    observes the maintenance UID only while the fixed local socket is opened.
    No database credential, role grant or authentication configuration changes.
    """
    if os.geteuid() != 0 or threading.active_count() != 1:
        raise BulletinError("bulletin_operator_connection_requires_single_root_thread")
    identity = pwd.getpwnam("smithguard-maintenance").pw_uid
    if identity <= 0:
        raise BulletinError("bulletin_operator_maintenance_identity_invalid")
    try:
        os.seteuid(identity)
        return psycopg.connect(
            dbname="smithguard",
            user="smithguard-maintenance",
            host="/run/postgresql",
            port=5432,
            connect_timeout=5,
            options="-c statement_timeout=10000 -c lock_timeout=5000",
        )
    finally:
        os.seteuid(0)


def status_tick(session, *, registry, grant_reader=current_grant, now):
    """Neutral events never depend on continued permission to publish new facts."""
    stream = store.lock_stream(session, now=now)
    try:
        grant = grant_reader(now=now)
        stream.mode = grant["mode"]
        stream.grant_hash = sha256_id(canonical_json_bytes(grant))
    except (ValueError, OSError):
        grant = None
        stream.mode = "paused"
    changed = 0
    # Source IDs are small, fixed register keys. Read only the distinct references,
    # including historical revisions so revocation cannot leave an old copy public.
    refs = func.jsonb_array_elements(BulletinPublicVersion.document["sources"]).table_valued(
        "value", joins_implicitly=True
    )
    source_ids = session.scalars(
        select(refs.c.value.op("->>")("source_id"))
        .select_from(BulletinPublicVersion, refs)
        .where(BulletinPublicVersion.tombstoned.is_(False))
        .distinct()
        .limit(101)
    ).all()
    if len(source_ids) > 100:
        raise BulletinError("bulletin_source_inventory_limit")
    for source_id in source_ids:
        try:
            profile = registry.get(source_id)
            revoked = not profile.is_public_output_approved
            overdue = date.fromisoformat(profile.source["rights"]["review_due_on"]) < now.date()
            disabled = not profile.source["kill_switch"]
        except SourceRightsError:
            revoked, overdue, disabled = True, False, False
        if not revoked:
            allowed, prohibited = set(), set()
            for rule in profile.field_rules:
                target = (
                    allowed
                    if rule["public_output"].startswith(("allowed", "normalized_fact"))
                    else prohibited
                )
                target.update(rule["fields"])
            # A narrower field rule can revoke old public bytes without revoking
            # the entire publisher. Inspect historical references as well.
            bad_fields = session.scalars(
                select(BulletinPublicVersion.bulletin_id)
                .select_from(BulletinPublicVersion, refs)
                .where(
                    BulletinPublicVersion.tombstoned.is_(False),
                    refs.c.value.op("->>")("source_id") == source_id,
                    ~refs.c.value.op("->")("used_fields").op("<@")(
                        cast(sorted(allowed - prohibited), JSONB)
                    ),
                )
                .distinct()
                .order_by(BulletinPublicVersion.bulletin_id)
                .limit(501 - changed)
            ).all()
            remaining = 500 - changed
            for identity in bad_fields[:remaining]:
                store.tombstone(session, identity, now=now)
                changed += 1
            if len(bad_fields) > remaining:
                stream.status_checked_at = None
                return {"status": "incomplete", "changed": changed}
        if not (revoked or overdue or disabled):
            continue
        reason = "rights_review_due" if overdue and stream.mode != "paused" else "policy_paused"
        matching = select(BulletinPublicVersion.bulletin_id).where(
            BulletinPublicVersion.document.contains({"sources": [{"source_id": source_id}]}),
            BulletinPublicVersion.tombstoned.is_(False),
        )
        identities = session.scalars(
            select(BulletinCurrent.bulletin_id)
            .where(
                BulletinCurrent.bulletin_id.in_(matching),
                BulletinCurrent.tombstoned.is_(False),
                True if revoked else BulletinCurrent.freshness_reason.is_distinct_from(reason),
            )
            .order_by(BulletinCurrent.bulletin_id)
            .limit(501 - changed)
        ).all()
        remaining = 500 - changed
        for identity in identities[:remaining]:
            if revoked:
                store.tombstone(session, identity, now=now)
            else:
                store.mark_stale(session, identity, reason=reason, now=now)
            changed += 1
        if len(identities) > remaining:
            # A bounded corrective tail is never advertised as fully checked.
            stream.status_checked_at = None
            return {"status": "incomplete", "changed": changed}
    if stream.mode == "paused":
        identities = session.scalars(
            select(BulletinCurrent.bulletin_id)
            .where(
                BulletinCurrent.tombstoned.is_(False),
                BulletinCurrent.freshness_reason.is_distinct_from("policy_paused"),
            )
            .order_by(BulletinCurrent.bulletin_id)
            .limit(501 - changed)
        ).all()
        remaining = 500 - changed
        for identity in identities[:remaining]:
            store.mark_stale(session, identity, reason="policy_paused", now=now)
            changed += 1
        if len(identities) > remaining:
            stream.status_checked_at = None
            return {"status": "incomplete", "changed": changed}
    changed += store.status_tick(session, now=now)
    return {"status": "complete", "changed": changed, "mode": stream.mode}


@contextmanager
def operator_lock(enabled, *, now):
    if not enabled:
        yield
        return
    from smithguard.deploy.mutation import mutation_owner

    # The database decision consumes the manual approval atomically. This host
    # lock only excludes release switches while the operator checks and writes.
    with mutation_owner(
        Path("/opt/SmithGuard/.deploy-mutations"),
        operation_id=now.strftime("%Y%m%d-") + uuid.uuid4().hex,
        phase="bulletin_operator",
        read_only=True,
    ) as owner:
        if owner.pending_path.exists():
            raise BulletinError("bulletin_deployment_pending")
        yield


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--status-tick", action="store_true")
    action.add_argument("--status", action="store_true")
    action.add_argument("--review-queue", action="store_true")
    action.add_argument("--observe", action="store_true")
    action.add_argument("--repair-expiry", type=Path)
    action.add_argument("--resolve-review", type=Path)
    action.add_argument("--publish", type=Path)
    action.add_argument("--verify", metavar="BULLETIN_ID")
    action.add_argument("--takedown", metavar="BULLETIN_ID")
    parser.add_argument("--approval-id")
    parser.add_argument("--content-hash")
    expected = parser.add_mutually_exclusive_group()
    expected.add_argument("--expect-absent", action="store_true")
    expected.add_argument("--expected-content-hash")
    parser.add_argument("--expected-revision", type=int)
    args = parser.parse_args(argv)
    engine = None
    try:
        if bool(args.approval_id) != bool(args.publish or args.verify):
            raise BulletinError("bulletin_manual_approval_required")
        if bool(args.content_hash) != bool(args.verify):
            raise BulletinError("bulletin_verification_hash_required")
        if (
            (args.expect_absent or args.expected_content_hash or args.expected_revision is not None)
            and not args.publish
        ) or (bool(args.expected_content_hash) != (args.expected_revision is not None)):
            raise BulletinError("bulletin_expected_state_invalid")
        if args.expected_content_hash and (
            not re.fullmatch(r"sha256:[a-f0-9]{64}", args.expected_content_hash)
            or args.expected_revision < 1
        ):
            raise BulletinError("bulletin_expected_state_invalid")
        # Explicit operator mutations require the existing root/maintenance route.
        # The unprivileged timer may only append neutral status/takedown events.
        if (
            args.publish
            or args.verify
            or args.takedown
            or args.review_queue
            or args.resolve_review
            or args.observe
            or args.repair_expiry
        ) and os.geteuid() != 0:
            raise BulletinError("bulletin_operator_required")
        if (
            args.publish
            or args.verify
            or args.takedown
            or args.review_queue
            or args.resolve_review
            or args.observe
            or args.repair_expiry
        ):
            engine = create_engine(
                "postgresql+psycopg://",
                creator=operator_connection,
                poolclass=NullPool,
                hide_parameters=True,
            )
        else:
            engine = create_engine(
                _validate_database_url(os.environ["SMITHGUARD_DATABASE_URL"]),
                poolclass=NullPool,
                hide_parameters=True,
                connect_args={
                    "connect_timeout": 5,
                    "options": "-c statement_timeout=10000 -c lock_timeout=5000",
                },
            )
        now = datetime.now(UTC)
        registry = RightsRegistry.from_path(rights_registry_path())
        with (
            operator_lock(
                bool(
                    args.publish
                    or args.verify
                    or args.takedown
                    or args.review_queue
                    or args.resolve_review
                    or args.observe
                    or args.repair_expiry
                ),
                now=now,
            ),
            Session(engine) as session,
            session.begin(),
        ):
            if args.observe:
                from sqlalchemy import text

                from smithguard.bulletin_observation import observe

                session.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"))
                session.execute(text("SET LOCAL statement_timeout='25s'"))
                result = observe(session, now=now)
            elif args.repair_expiry:
                from smithguard.bulletin_expiry_repair import repair

                request = strict_json_loads(
                    _secure_file(args.repair_expiry, label="expiry repair", maximum=16384)
                )
                result = repair(session, request, grant=current_grant(now=now), now=now)
            elif args.review_queue:
                from smithguard.bulletin_review import queue

                result = queue(session)
            elif args.resolve_review:
                from smithguard.bulletin_review import resolve

                value = strict_json_loads(
                    _secure_file(args.resolve_review, label="review resolution", maximum=16384)
                )
                result = resolve(session, value, now=now)
            elif args.status:
                result = store.source_status(session, now=now)
            elif args.status_tick:
                result = status_tick(session, registry=registry, now=now)
            elif args.takedown:
                result = {"tombstoned": store.tombstone(session, args.takedown, now=now)}
            else:
                grant = current_grant(now=now)
                if args.publish:
                    document = strict_json_loads(
                        _secure_file(args.publish, label="bulletin draft", maximum=24576)
                    )
                    if args.expect_absent or args.expected_content_hash:
                        validate_content(document, now=now)
                        # The same stream lock remains held through publish and commit.
                        # A concurrent writer cannot change the reviewed baseline here.
                        store.lock_stream(session, now=now)
                        current = session.get(BulletinCurrent, content_id(document))
                        if args.expect_absent:
                            if current is not None:
                                raise BulletinError("bulletin_current_changed")
                        else:
                            if current is None or current.revision != args.expected_revision:
                                raise BulletinError("bulletin_current_changed")
                            previous = session.get(
                                BulletinRevision, (current.bulletin_id, current.revision)
                            )
                            if (
                                previous is None
                                or previous.content_hash != args.expected_content_hash
                            ):
                                raise BulletinError("bulletin_current_changed")
                    record = store.publish(
                        session,
                        document,
                        grant=grant,
                        registry=registry,
                        now=now,
                        manual_approval=args.approval_id,
                    )
                    result = {"bulletin_id": record["bulletin_id"], "revision": record["revision"]}
                else:
                    store.verify_unchanged(
                        session,
                        args.verify,
                        content_hash=args.content_hash,
                        grant=grant,
                        registry=registry,
                        now=now,
                        manual_approval=args.approval_id,
                    )
                    result = {"verified": args.verify}
        print(json.dumps(result, sort_keys=True, default=timestamp))
        return 0
    except Exception as error:
        print(
            json.dumps(
                {
                    "status": "failed",
                    "error_class": type(error).__name__,
                    "observed_at": timestamp(datetime.now(UTC)),
                }
            )
        )
        return 1
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
