#!/usr/bin/env python3
"""Render an exact shadow or active warning-lane policy without manual JSON edits."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

from smithguard.identifiers import canonical_json_bytes
from smithguard.spend import SpendPolicyError, render_spend_policy_state


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--state", choices=("shadow", "active"), required=True)
    parser.add_argument("--approval-id")
    return parser.parse_args()


def render_to_path(
    *,
    source: Path,
    output: Path,
    state: str,
    approval_id: str | None,
) -> None:
    if not source.is_file():
        raise SpendPolicyError("source policy is absent")
    document = json.loads(source.read_text(encoding="utf-8"))
    rendered = render_spend_policy_state(
        document,
        state=state,
        approval_id=approval_id,
    )
    output.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.",
        dir=output.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_json_bytes(rendered) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    arguments = _arguments()
    render_to_path(
        source=arguments.source,
        output=arguments.output,
        state=arguments.state,
        approval_id=arguments.approval_id,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
