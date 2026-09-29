"""Exact-commit release with content identity checks and safe reruns (FR-74)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from pathlib import Path


def command(*args: str) -> str:
    return subprocess.check_output(args, text=True).strip()


def validate_version(requested: str, actual: str) -> None:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", requested) or requested != actual:
        raise ValueError("Requested X.Y.Z must exactly match pyproject.toml")


def identities(directory: Path) -> dict[str, str]:
    return {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(directory.iterdir())
        if p.is_file() and p.name != "SHA256SUMS"
    }


def compare_assets(expected: dict[str, str], existing: dict[str, str]) -> None:
    for name, digest in existing.items():
        if expected.get(name) != digest:
            raise ValueError(f"Published asset differs: {name}; assets are immutable")


def main() -> None:
    requested = os.environ["RELEASE_VERSION"]
    actual = tomllib.loads(Path("pyproject.toml").read_text())["project"]["version"]
    validate_version(requested, actual)
    tag = "v" + requested
    if sys.argv[1] == "freeze":
        if os.environ.get("GITHUB_REF", "refs/heads/main") != "refs/heads/main":
            raise ValueError("Dispatch releases from main so workflow definitions are trusted")
        sha = command("git", "rev-parse", "HEAD")
        existing = subprocess.run(
            ["git", "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}"],
            capture_output=True,
            text=True,
            check=False,
        )
        if existing.returncode == 0:
            frozen = existing.stdout.strip()
            if frozen != sha:
                raise ValueError("Existing version tag points elsewhere; refusing to move it")
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            stream.write(f"sha={sha}\n")
        return
    sha = os.environ["RELEASE_SHA"]
    if command("git", "rev-parse", "HEAD") != sha:
        raise ValueError("Publish checkout does not match the frozen commit")
    directory = Path("dist")
    wheels = list(directory.glob("*.whl"))
    sdists = list(directory.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise ValueError("Expected exactly one wheel and one source distribution")
    with zipfile.ZipFile(wheels[0]) as wheel:
        metadata = wheel.read(
            next(n for n in wheel.namelist() if n.endswith(".dist-info/METADATA"))
        ).decode()
        if f"\nVersion: {requested}\n" not in metadata:
            raise ValueError("Wheel version differs from release version")
    with tarfile.open(sdists[0]) as archive:
        source = archive.extractfile(
            next(m for m in archive.getmembers() if m.name.endswith("/pyproject.toml"))
        )
        assert source is not None
        validate_version(requested, tomllib.loads(source.read().decode())["project"]["version"])
    manifest = identities(directory)
    (directory / "SHA256SUMS").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in manifest.items()), encoding="utf-8"
    )
    expected = {
        "SHA256SUMS": hashlib.sha256((directory / "SHA256SUMS").read_bytes()).hexdigest(),
        **manifest,
    }
    changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
    marker = f"## {requested}\n"
    if marker not in changelog:
        raise ValueError("Changelog is missing the release section")
    release_notes = changelog.split(marker, 1)[1].split("\n## ", 1)[0]
    repo = os.environ["GITHUB_REPOSITORY"]
    ref = subprocess.run(
        ["gh", "api", f"repos/{repo}/git/ref/tags/{tag}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if ref.returncode == 0:
        obj = json.loads(ref.stdout)["object"]
        target = obj["sha"]
        if obj["type"] == "tag":
            target = json.loads(command("gh", "api", f"repos/{repo}/git/tags/{target}"))["object"][
                "sha"
            ]
        if target != sha:
            raise ValueError("Existing tag points to a different commit")
    else:
        subprocess.run(
            [
                "gh",
                "api",
                f"repos/{repo}/git/refs",
                "-f",
                f"ref=refs/tags/{tag}",
                "-f",
                f"sha={sha}",
            ],
            check=True,
        )
    release = subprocess.run(
        ["gh", "release", "view", tag, "--json", "isDraft,assets"],
        capture_output=True,
        text=True,
        check=False,
    )
    if release.returncode != 0:
        with tempfile.TemporaryDirectory() as temp:
            notes = Path(temp) / "notes.md"
            notes.write_text(release_notes, encoding="utf-8")
            subprocess.run(
                [
                    "gh",
                    "release",
                    "create",
                    tag,
                    "--verify-tag",
                    "--draft",
                    "--title",
                    tag,
                    "--notes-file",
                    str(notes),
                ],
                check=True,
            )
        metadata_release = {"isDraft": True, "assets": []}
    else:
        metadata_release = json.loads(release.stdout)
    existing_names = [a["name"] for a in metadata_release["assets"]]
    with tempfile.TemporaryDirectory() as temp:
        if existing_names:
            subprocess.run(["gh", "release", "download", tag, "--dir", temp], check=True)
        found = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(temp).iterdir()}
        compare_assets(expected, found)
        if (
            not metadata_release["isDraft"]
            and set(found) != set(expected)
            and "SHA256SUMS" not in found
        ):
            raise ValueError(
                "Incomplete published release has no identity manifest; refusing to add assets"
            )
    for name in expected:
        if name not in existing_names:
            subprocess.run(["gh", "release", "upload", tag, str(directory / name)], check=True)
    if metadata_release["isDraft"]:
        subprocess.run(["gh", "release", "edit", tag, "--draft=false"], check=True)


if __name__ == "__main__":
    main()
