"""Lưu cache phần phụ thuộc tại thời điểm chuẩn bị.

Quá trình xác minh không được truy cập mạng. Các artifact Maven được phân giải một lần,
tại thời điểm chuẩn bị, vào một thư mục cache mà quá trình xác minh sẽ tái sử dụng.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path


@dataclass
class PreparedCache:
    """Bản ghi những gì đã được cache tại thời điểm chuẩn bị."""

    m2_cache_dir: Path
    cache_key: str
    items: list[str]


def cache_key_for(pom_xml: Path) -> str:
    """Khóa ổn định từ nội dung POM (không phải đường dẫn hoặc timestamp)."""
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
    """Phân giải các phụ thuộc một lần vào cache_root/<key>/.m2.

    Không bao giờ được gọi trong quá trình xác minh: đây chỉ là bước tại thời điểm chuẩn bị.
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
        check=False,  # bước chuẩn bị được thực hiện theo khả năng tốt nhất; bước xác minh sẽ báo cáo các khoảng trống
        capture_output=True,
        timeout=900,
    )

    items = sorted(p.name for p in m2.rglob("*") if p.is_file())
    return PreparedCache(
        m2_cache_dir=m2,
        cache_key=key,
        items=items,
    )
