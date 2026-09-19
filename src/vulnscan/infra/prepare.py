"""Preparation-time dependency caching.

Verification must not hit the network. Maven artifacts are resolved once,
at preparation time, into a cache directory that verification reuses.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path


@dataclass
class PreparedCache:
    """Record of what was cached at preparation time."""
    m2_cache_dir: Path
    cache_key: str
    items: list[str]


def cache_key_for(pom_xml: Path) -> str:
    """Stable key from the POM contents (not the path or timestamp)."""
    h = hashlib.sha256()
    with pom_xml.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def prepare_maven_cache(
    project_dir: Path,
    cache_root: Path,
    maven_cmd: str = "mvn.cmd",
    java_home: str = "C:/Program Files/Java/jdk-17",
) -> PreparedCache:
    """Resolve dependencies once into cache_root/<key>/.m2.

    Never called during verification: this is preparation-time only.
    """
    project_dir = Path(project_dir)
    pom = project_dir / "pom.xml"
    if not pom.exists():
        raise FileNotFoundError(f"no pom.xml in {project_dir}")

    key = cache_key_for(pom)
    m2 = Path(cache_root) / key / ".m2"
    m2.mkdir(parents=True, exist_ok=True)

    import os
    import subprocess

    env = dict(os.environ)
    env["JAVA_HOME"] = java_home
    env["MAVEN_OPTS"] = f"-Dmaven.repo.local={m2}"

    subprocess.run(
        [maven_cmd, "-B", "-DskipTests", "dependency:go-offline"],
        cwd=str(project_dir),
        env=env,
        check=False,  # preparation is best-effort; verification reports gaps
        capture_output=True,
        timeout=900,
    )

    items = sorted(p.name for p in m2.rglob("*") if p.is_file())
    return PreparedCache(
        m2_cache_dir=m2,
        cache_key=key,
        items=items,
    )
