# Đóng góp mới: engine săn lỗ hổng tự xây (native-hunt)

> Số liệu trên WebGoat `3284a8e` (291 file Java + static JS), so với semgrep 1.78.0
> cùng 85 rules. Tái hiện: `scan_snapshot('harness/WebGoat', [...])`.

## Kết quả ablation (đếm theo dòng file+line)

| Cấu hình | Dòng có finding |
|---|---|
| A. Semgrep (baseline, đồ có sẵn) | 49 |
| B. Native-hunt (đồ tự xây) | 159 |
| Giao nhau A ∩ B | 43 (88% của A) |
| Chỉ A có (6) | 4 bundle vendored minified (bỏ qua có chủ đích — chính semgrep cũng timeout trên ace.js) + 1 lệch dòng cùng finding (KID, tolerance ±3) + 1 chuỗi process-I/O (giới hạn v1, đã ghi nhận) |
| Chỉ B có, High/Medium | 34+ (SQLi Lesson2/3/4, ChallengeLogin, KID JWT, log-injection, reflection, default-encoding...) mà semgrep mù |

Đọc đúng: native **bao phủ 88% semgrep và tìm thêm** các luồng taint đa bước
(inter-procedural, multi-line) mà pattern một dòng của semgrep bỏ sót.

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
