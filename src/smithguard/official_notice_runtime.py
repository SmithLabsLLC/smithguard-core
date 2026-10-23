"""Internal official-notice worker and read-only status; no inference credentials."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from smithguard.bulletin_intake import run
from smithguard.bulletin_intake_status import status
from smithguard.bulletin_publisher import processor
from smithguard.identifiers import strict_json_loads, timestamp
from smithguard.official_notice_fetch import ENDPOINTS, selected_sources
from smithguard.runtime import _validate_database_url
from smithguard.source_rights import RightsRegistry

CONTROL_DIRECTORY = Path("/etc/SmithGuard/policies")
CONTROL_PATH = CONTROL_DIRECTORY / "official-notices.json"
CONTROL_UID = 0
CURRENT_RELEASE = Path("/opt/SmithGuard/current")


def running_release():
    root = CURRENT_RELEASE.resolve(strict=True)
    if (
        not CURRENT_RELEASE.is_symlink()
        or not re.fullmatch(r"[a-f0-9]{40}", root.name)
        or not Path(__file__).resolve().is_relative_to(root)
    ):
        raise ValueError("official_running_release_invalid")
    return root.name


def rights_registry_path():
    commit = running_release()
    root = CURRENT_RELEASE.resolve(strict=True)
    if root.name != commit:
        raise ValueError("official_running_release_changed")
    return root / "contracts/v1/source-rights-register.json"


def control_bytes(*, operation_id, artifact_commit, enabled=False, source_keys=None):
    document = {
        "schema_version": 1,
        "operation_id": operation_id,
        "artifact_commit": artifact_commit,
        "enabled": enabled,
    }
    if source_keys is not None:
        document["source_keys"] = list(selected_sources(source_keys))
    validate_control(document)
    return (json.dumps(document, sort_keys=True) + "\n").encode("ascii")


def validate_control(document):
    if (
        not isinstance(document, dict)
        or set(document) - {"source_keys"}
        != {"schema_version", "operation_id", "artifact_commit", "enabled"}
        or type(document["schema_version"]) is not int
        or document["schema_version"] != 1
        or type(document["enabled"]) is not bool
        or not isinstance(document["operation_id"], str)
        or not re.fullmatch(r"[0-9]{8}-[a-f0-9]{32}", document["operation_id"])
        or not (
            document["artifact_commit"] is None
            and not document["enabled"]
            or isinstance(document["artifact_commit"], str)
            and re.fullmatch(r"[a-f0-9]{40}", document["artifact_commit"])
        )
    ):
        raise ValueError("official_control_invalid")
    selected_sources(document.get("source_keys", tuple(ENDPOINTS)))
    return document


def read_control():
    metadata = CONTROL_DIRECTORY.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != CONTROL_UID
        or metadata.st_mode & 0o022
        or CONTROL_PATH.parent != CONTROL_DIRECTORY
    ):
        raise ValueError("official_control_directory_unsafe")
    descriptor = os.open(CONTROL_PATH, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != CONTROL_UID
            or stat.S_IMODE(metadata.st_mode) != 0o644
            or metadata.st_nlink != 1
            or metadata.st_size > 4096
        ):
            raise ValueError("official_control_unsafe")
        document = validate_control(strict_json_loads(stream.read(4097)))
    if document["enabled"] and document["artifact_commit"] != running_release():
        raise ValueError("official_control_release_mismatch")
    return document


def control_state():
    try:
        control = read_control()
    except (OSError, ValueError, TypeError):
        return {"state": "unavailable", "reason": "control_missing_unsafe_or_release_mismatch"}
    return {
        "state": "enabled" if control["enabled"] else "paused",
        "operation_id": control["operation_id"],
        "artifact_commit": control["artifact_commit"],
    }


def enabled():
    return control_state()["state"] == "enabled"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--run", action="store_true")
    mode.add_argument("--status", action="store_true")
    args = parser.parse_args(argv)
    control = control_state()
    if args.run and control["state"] != "enabled":
        print(json.dumps({"status": control["state"], "control": control, "network_attempts": 0}))
        return 0 if control["state"] == "paused" else 1
    engine = None
    try:
        url = _validate_database_url(os.environ["SMITHGUARD_DATABASE_URL"])
        engine = create_engine(
            url,
            poolclass=NullPool,
            hide_parameters=True,
            connect_args={
                "connect_timeout": 5,
                "options": "-c statement_timeout=10000 -c lock_timeout=5000",
            },
        )
        if args.status:
            with Session(engine) as session, session.begin():
                # The status path never creates a receipt or opens a feed connection.
                result = status(session, now=datetime.now(UTC))
                result["control"] = control
        else:
            invocation = os.environ.get("INVOCATION_ID")
            if invocation is not None and not re.fullmatch(r"[a-f0-9]{32}", invocation):
                raise ValueError("official_invocation_invalid")
            from smithguard.bulletin_intake import no_publication
            from smithguard.bulletin_runtime import current_grant

            registry = RightsRegistry.from_path(rights_registry_path())
            try:
                grant = current_grant(now=datetime.now(UTC))
            except (OSError, ValueError):
                grant = None
            process = (
                processor(registry=registry, grant_reader=current_grant)
                if grant and grant["mode"] != "paused"
                else no_publication
            )
            result = run(
                engine,
                enabled=enabled,
                artifact_commit=running_release(),
                invocation_id=invocation,
                registry=registry,
                process=process,
                source_keys=read_control().get("source_keys", tuple(ENDPOINTS)),
            )
            if grant and "kev" in grant["source_keys"] and grant["mode"] != "paused":
                from smithguard.bulletin_kev import run as kev_run

                with Session(engine) as session, session.begin():
                    result["kev"] = kev_run(
                        session,
                        registry=registry,
                        grant_reader=current_grant,
                        now=datetime.now(UTC),
                    )
        print(json.dumps(result, sort_keys=True))
        return (
            0
            if args.status
            or result["status"]
            in {
                "complete",
                "degraded",
                "paused",
                "busy",
                "hour_consumed",
                "storage_budget_paused",
                "identity_budget_paused",
            }
            else 1
        )
    except Exception as error:
        # Exception messages may contain database connection or upstream content.
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
