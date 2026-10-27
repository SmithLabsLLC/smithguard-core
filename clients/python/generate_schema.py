"""Generate only transitive public assessment definitions, preserving source conditions."""

import json
from pathlib import Path


def render(source):
    defs = source["$defs"]
    selected = {}
    pending = ["PublicArtifactAssessment"]
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        selected[name] = defs[name]
        nodes = [defs[name]]
        while nodes:
            node = nodes.pop()
            if isinstance(node, dict):
                if "$ref" in node:
                    ref = node["$ref"]
                    if not ref.startswith("#/$defs/") or "/" in ref[8:]:
                        raise ValueError("nonlocal schema reference")
                    pending.append(ref[8:])
                nodes.extend(node.values())
            elif isinstance(node, list):
                nodes.extend(node)
    if any(name.startswith(("Private", "Inventory", "Local", "Replay")) for name in selected):
        raise ValueError("private definition in public schema closure")
    return (
        json.dumps(
            {
                "$schema": source["$schema"],
                "$ref": "#/$defs/PublicArtifactAssessment",
                "$defs": selected,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode()


if __name__ == "__main__":
    import sys

    Path(sys.argv[2]).write_bytes(render(json.loads(Path(sys.argv[1]).read_bytes())))
