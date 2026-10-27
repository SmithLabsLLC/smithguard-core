"""Explicit preview, hash-bound disclosure consent, finite checks and private output."""

from __future__ import annotations

import argparse
import fcntl
import signal
import sys
from threading import Event

from .discovery import artifact, discover
from .report import html_report, text_report
from .run import run
from .storage import PrivateDirectory
from .transport import PublicReader, approved_coordinates


def parser():
    root = argparse.ArgumentParser(
        prog="smithguard-client",
        description="Opt-in Linux Python metadata preview and hosted public-coordinate assessment.",
    )
    commands = root.add_subparsers(dest="command", required=True)
    preview = commands.add_parser(
        "preview", help="Read only selected metadata; no network requests."
    )
    preview.add_argument(
        "--scope",
        action="append",
        required=True,
        help="Absolute site-packages directory; repeated up to 32 times. No symlink ancestors.",
    )
    preview.add_argument(
        "--public",
        action="append",
        default=[],
        metavar="NAME==VERSION",
        help=(
            "Explicit assertion that this exact coordinate may be co"
            "nsidered public; not installed identity proof."
        ),
    )
    preview.add_argument(
        "--application",
        action="append",
        default=[],
        metavar="SCOPE_NUMBER:NAME",
        help="Explicit parent application root, using a 1-based --scope index.",
    )
    preview.add_argument(
        "--output",
        required=True,
        help="New private local directory, beneath an existing real directory.",
    )
    execute = commands.add_parser(
        "run", help="Revalidate preview and send only its explicitly approved coordinates."
    )
    execute.add_argument("--directory", required=True, help="Existing private preview directory.")
    execute.add_argument(
        "--approve",
        required=True,
        metavar="PREVIEW_SHA256",
        help="Explicit consent to disclose exactly the preview list and stated protocol metadata.",
    )
    execute.add_argument("--budget-seconds", type=float, default=300)
    execute.add_argument(
        "--resume",
        metavar="STATE_FILENAME",
        help="Resume minimal progress; every coordinate is checked again.",
    )
    execute.add_argument(
        "--local-facts",
        metavar="FILENAME",
        help=(
            "Optional private JSON in the preview directory, keyed by installation ID. Never sent."
        ),
    )
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if not sys.platform.startswith("linux"):
            raise ValueError("this discovery adapter supports Linux only")
        if args.command == "preview":
            public = []
            for value in args.public:
                if value.count("==") != 1:
                    raise ValueError("--public requires NAME==VERSION")
                public.append(artifact(*value.split("==")))
            roots = {}
            for value in args.application:
                index, name = value.split(":", 1)
                number = int(index)
                if not 1 <= number <= len(args.scope):
                    raise ValueError("application scope index out of bounds")
                roots.setdefault(args.scope[number - 1], []).append(name)
            preview = discover(args.scope, approved_public=public, application_roots=roots)
            import json

            with PrivateDirectory(args.output, create=True) as output:
                output.write_json("preview.json", preview)
                output.write(
                    "preview.txt",
                    (
                        preview["disclosure"]
                        + "\n\nExact proposed egress list:\n"
                        + json.dumps(preview["coordinates"], indent=2, ensure_ascii=True)
                        + "\n\nApproval SHA256: "
                        + preview["approval_sha256"]
                        + "\n"
                    ).encode(),
                )
            print("Preview created. Read preview.txt before approving disclosure.")
            print("Approval SHA256: " + preview["approval_sha256"])
            return 0
        with PrivateDirectory(args.directory) as output:
            # One writer for this private directory; no lockfile replacement.
            fcntl.flock(output.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            preview = output.read_json("preview.json")
            approved_coordinates(preview, args.approve)
            current = discover(
                preview["scopes"],
                approved_public=preview["coordinates"],
                application_roots=preview["application_roots"],
            )
            if current["approval_sha256"] != args.approve:
                raise ValueError(
                    "selected metadata or scope changed; create and approve a new preview"
                )
            resume = output.read_json(args.resume) if args.resume else None
            facts = output.read_json(args.local_facts) if args.local_facts else None
            stopped = Event()

            def cancel(_signum, _frame):
                stopped.set()

            reader = PublicReader(budget_seconds=args.budget_seconds, stopped=stopped)
            old_int = signal.signal(signal.SIGINT, cancel)
            old_term = signal.signal(signal.SIGTERM, cancel)
            previous = None
            filename = None

            def checkpoint(state):
                nonlocal previous, filename
                if previous is None and state.get("stale_fact_sets_at_start"):
                    print(
                        str(state["stale_fact_sets_at_start"])
                        + " supplied fact sets are stale; interpretation will be incomplete."
                    )
                filename = "state-" + state["run_id"] + ".json"
                previous = output.replace_own_json(filename, state, previous_sha256=previous)

            try:
                report, state = run(
                    current,
                    args.approve,
                    reader=reader,
                    resume=resume,
                    checkpoint=checkpoint,
                    local_facts=facts,
                )
                prefix = "report-" + state["run_id"]
                state["report_exports"] = {"status": "writing", "files": []}
                checkpoint(state)
                try:
                    output.write_json(prefix + ".json", report)
                    state["report_exports"]["files"].append(prefix + ".json")
                    checkpoint(state)
                    for suffix, render in ((".html", html_report), (".txt", text_report)):
                        output.write(prefix + suffix, render(report))
                        state["report_exports"]["files"].append(prefix + suffix)
                        checkpoint(state)
                    state["report_exports"]["status"] = "complete"
                    checkpoint(state)
                except (OSError, ValueError, KeyError, TypeError) as exc:
                    state["report_exports"].update(status="failed", error_type=type(exc).__name__)
                    checkpoint(state)
                    raise
            finally:
                reader.close()
                signal.signal(signal.SIGINT, old_int)
                signal.signal(signal.SIGTERM, old_term)
            print("Private local report: " + prefix + ".html")
            print("Minimal progress: " + filename)
            counts = report["counts"]
            print(
                str(counts["installations"])
                + " installations; "
                + str(counts["approved_coordinates"])
                + " approved coordinates."
            )
            print(
                "Completed checks: "
                + str(report["run_complete"])
                + ". Discovery scope complete: "
                + str(report["scope_complete"])
                + "."
            )
            print("Installation statuses: " + str(counts["installation_statuses"]))
            print(
                "Evidence complete: "
                + str(report["evidence_complete"])
                + ". Interpretation complete: "
                + str(report["interpretation_complete"])
                + ". Supplied fact sets not fully evaluated: "
                + str(counts["supplied_facts_not_fully_evaluated"])
                + "."
            )
            return (
                0
                if all(
                    report[k]
                    for k in (
                        "run_complete",
                        "scope_complete",
                        "evidence_complete",
                        "interpretation_complete",
                    )
                )
                else 2
            )
    except (OSError, ValueError, KeyError, TypeError) as exc:
        # Never print exception strings that may contain paths, private names, URLs
        # or network headers. Detailed derived evidence stays only in private files.
        print(
            "Could not complete: "
            + type(exc).__name__
            + ". Check selected paths, permissions, preview identity and input format.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
