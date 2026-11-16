"""Khử trùng lặp finding một cách thận trọng (conservative).

Khóa khử trùng lặp: vân tay (fingerprint) của finding (location + cwe + sorted rule ids).
Không bao giờ gộp chỉ vì nhãn CWE trùng nhau — bằng chứng về vị trí và rule
phải khớp nhau. Mọi observation đóng góp từ mỗi bản trùng lặp đều được gộp
vào finding còn lại để không làm mất thông tin nào.
"""

from __future__ import annotations

from vulnscan.contracts import Finding


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Loại bỏ các bản trùng lặp chính xác theo fingerprint, gộp các observation vào.

    Hai finding có cùng CWE nhưng khác fingerprint (khác vị trí
    hoặc bằng chứng rule) sẽ được giữ riêng biệt.
    """
    seen: dict[str, Finding] = {}
    order: list[str] = []

    for f in findings:
        fp = f.fingerprint
        if fp in seen:
            # Bảo toàn nguồn gốc (provenance): gộp các observation của bản trùng lặp vào.
            keeper = seen[fp]
            ids = {o.observation_id for o in keeper.observations}
            for obs in f.observations:
                if obs.observation_id not in ids:
                    keeper.observations.append(obs)
                    keeper.evidence_refs.append(obs.observation_id)
            for g in f.groups:
                if g.group_id not in {kg.group_id for kg in keeper.groups}:
                    keeper.groups.append(g)
            continue
        seen[fp] = f
        order.append(fp)

    return [seen[fp] for fp in order]
