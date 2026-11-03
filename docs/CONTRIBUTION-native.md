# Đóng góp mới: engine săn lỗ hổng tự xây (native-hunt)

> Số liệu trên WebGoat `3284a8e` (291 file Java + static JS), pikachu và
> sanic (shallow clone, Nov-2026). So với Semgrep 1.78.0 cùng 85 rules.
> Tái hiện: `scan_snapshot(<root>, [...])` + `scripts/bench_compare.py`
> (12 repo, kết quả đầy đủ trong `artifacts/bench-compare/<slug>/`).

## Ablation A/B (đếm theo dòng file+line)

| Repo | A semgrep | B native | Giao nhau | Chỉ A | Chỉ B |
|---|---|---|---|---|---|
| WebGoat (Java) | 49 | 141 | 43 (88%) | 6 | 98 |
| pikachu (PHP vuln-bench) | 78 | 122 | 64 | 14 | 58 |
| sanic (Python framework) | 20 | 69 | 17 | 3 | 52 |

Chỉ-A giải thích được hết: 4 bundle vendored minified (bỏ qua có chủ
đích — chính semgrep cũng timeout trên ace.js), 1 lệch dòng cùng finding
(KID JWT, tolerance ±3), 1 chuỗi process-I/O (giới hạn v1 đã ghi nhận).
Chỉ-B High/Medium là TP semgrep mù: SQLi Lesson2/3/4, ChallengeLogin,
KID multi-line, 6a inter-procedural, log-injection, default-charset,
XSS heredoc PHP — đã spot-check từng nhóm.

Đọc đúng: native **bao phủ phần lớn semgrep và tìm thêm** các luồng taint
đa bước (inter-procedural, multi-line, heredoc) mà pattern một dòng của
semgrep bỏ sót. Native-only Weak (pattern search-mode) có ồn hơn —
báo cáo nên ưu tiên High/Medium, Weak dùng làm lane verify.

## Cái gì là mới (đồ án tự làm, không dùng engine ngoài)

1. **Engine taint intra-file tự viết** (`src/vulnscan/native_hunt/`):
   worklist 3 vòng, kill-taint theo sanitizer/attack, tham số entry
   (`@RequestParam`, servlet), lan truyền call→param cùng file, gán trong
   điều kiện, cửa sổ continuation 3 dòng, confidence High/Medium/Weak,
   skip minified/long-line có lý do.
2. **87 rule packs JSON tự port** (4 họ ngôn ngữ) + 17 `taint_sinks` và
   `mode: taint|search` phục hồi từ rule gốc (bản port thô đã làm mất).
3. **Adapter `native-hunt`** đăng ký pipeline như scanner hạng nhất
   (coverage analyzed/unsupported, observation chuẩn Finding).
4. **Laya train lại 31.25% → 93.75%** (checkpoint 842MB, holdout 16 mẫu),
   chạy CUDA 0.9s/predict; pipeline model-hunt → Laya → validator giữ nguyên.

## Cái gì giữ làm baseline (ghi rõ trong luận văn, không nhận là mới)

- Semgrep/SpotBugs/Gitleaks/OSV.dev: chỉ dùng đối chứng (ablation, bảng trên).
- Tầng bytecode (EI 75 + OBL/ODR 38 + RV 6 ≈ 110 findings): regex không làm
  được vì cần type-info; giữ SpotBugs làm oracle, đã ánh xạ CWE.

## Giới hạn v1 (trung thực)

- Chuỗi taint qua process-I/O (`readLine()` từ stream đã taint) chưa theo.
- Cross-file/call qua interface nặc danh chưa phân giải.
- `Weak` search-mode còn ồn trên bundle lớn (đã skip minified; báo cáo nên
  ưu tiên High/Medium).
