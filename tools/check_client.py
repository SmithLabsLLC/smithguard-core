"""Check the optional client, generated schema and installed release artifacts."""

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLIENT = ROOT / "clients/python"


def main():
    uv = shutil.which("uv")
    if not uv:
        raise SystemExit("Install the repository's pinned uv version first.")
    env = dict(os.environ, SOURCE_DATE_EPOCH="1793052000")
    env.pop("VIRTUAL_ENV", None)

    def run(*args):
        print("+", uv, *map(str, args), flush=True)
        return subprocess.run([uv, *map(str, args)], cwd=CLIENT, env=env, check=True)  # noqa: S603

    spec = importlib.util.spec_from_file_location(
        "client_schema_generator", CLIENT / "generate_schema.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    schema = module.render(
        json.loads((ROOT / "contracts/v1/contract-bundle.schema.json").read_bytes())
    )
    if schema != (CLIENT / "src/smithguard_client/schemas/assessment.json").read_bytes():
        raise SystemExit("Regenerate the client assessment schema from the public contract.")
    run("sync", "--locked")
    # A private temporary folder under the resolved tool environment avoids
    # execute-only session TMPDIR ancestors in strict path-opening fixtures.
    with tempfile.TemporaryDirectory(prefix="client-check-", dir=CLIENT / ".venv") as scratch:
        env["TMPDIR"] = scratch
        run("run", "--no-sync", "ruff", "check", "src", "tests", "generate_schema.py")
        run("run", "--no-sync", "ruff", "format", "--check", "src", "tests", "generate_schema.py")
        run("audit", "--locked", "--preview-features", "audit-command")
        with tempfile.TemporaryDirectory(prefix="smithguard-client-build-") as temporary:
            output = Path(temporary)
            for name in ("first", "second"):
                run("build", "--no-sources", "--out-dir", output / name)
            first = {f.name: f for f in (output / "first").iterdir() if not f.name.startswith(".")}
            second = {
                f.name: f for f in (output / "second").iterdir() if not f.name.startswith(".")
            }
            if len(first) != 2 or first.keys() != second.keys():
                raise SystemExit("Expected one wheel and one source archive per build.")
            for name, path in first.items():
                if path.read_bytes() != second[name].read_bytes():
                    raise SystemExit("Client build is not reproducible.")
                print(name, hashlib.sha256(path.read_bytes()).hexdigest())
            source_files = {
                str(f.relative_to(CLIENT / "src")): f
                for f in (CLIENT / "src").rglob("*")
                if f.is_file() and "__pycache__" not in f.parts and f.suffix != ".pyc"
            }
            wheel = next(f for f in first.values() if f.suffix == ".whl")
            with zipfile.ZipFile(wheel) as archive:
                names = archive.namelist()
                dist_info = wheel.name.removesuffix("-py3-none-any.whl") + ".dist-info/"
                metadata = {
                    dist_info + name
                    for name in (
                        "METADATA",
                        "WHEEL",
                        "entry_points.txt",
                        "licenses/LICENSE",
                        "RECORD",
                    )
                }
                if len(names) != len(set(names)) or set(names) != set(source_files) | metadata:
                    raise SystemExit("Wheel contains unexpected or duplicate files.")
                included = {n for n in names if n.startswith("smithguard_client/")}
                if included != source_files.keys():
                    raise SystemExit("Wheel file membership differs from client source.")
                for name, file in source_files.items():
                    if archive.read(name) != file.read_bytes():
                        raise SystemExit("Wheel bytes differ from client source.")
            sdist = next(f for f in first.values() if f.name.endswith(".tar.gz"))
            expected = {
                "README.md",
                "LICENSE",
                "pyproject.toml",
                "uv.lock",
                ".python-version",
                "THIRD_PARTY_NOTICES.md",
                "generate_schema.py",
                ".gitignore",
                "PKG-INFO",
            }
            expected.update("src/" + name for name in source_files)
            expected.update(
                str(f.relative_to(CLIENT))
                for f in (CLIENT / "tests").rglob("*")
                if f.is_file() and "__pycache__" not in f.parts and f.suffix != ".pyc"
            )
            with tarfile.open(sdist) as archive:
                all_members = archive.getmembers()
                prefix = sdist.name.removesuffix(".tar.gz") + "/"
                if any(not m.name.startswith(prefix) for m in all_members):
                    raise SystemExit("Source archive has an unexpected root path.")
                members = {m.name.removeprefix(prefix): m for m in all_members}
                if len(members) != len(all_members):
                    raise SystemExit("Source archive contains duplicate files.")
                if members.keys() != expected:
                    raise SystemExit("Source archive file membership differs from allowlist.")
                for name, member in members.items():
                    if not member.isfile() or member.issym() or member.islnk():
                        raise SystemExit("Source archive contains a nonregular file.")
                    if (
                        name != "PKG-INFO"
                        and archive.extractfile(member).read() != (CLIENT / name).read_bytes()
                    ):
                        raise SystemExit("Source archive bytes differ from client source.")
            run(
                "pip",
                "install",
                "--python",
                CLIENT / ".venv/bin/python",
                "--no-deps",
                "--force-reinstall",
                wheel,
            )
            run(
                "run",
                "--no-sync",
                "python",
                "-c",
                'import smithguard_client; assert "site-packages" in smithguard_client.__file__',
            )
            run(
                "run",
                "--no-sync",
                "python",
                "-m",
                "pytest",
                "-q",
                "-p",
                "no:cacheprovider",
                "tests",
            )
        print(
            "Client schema, dependency audit, reproducible packages "
            "and installed-wheel tests passed."
        )


if __name__ == "__main__":
    main()
