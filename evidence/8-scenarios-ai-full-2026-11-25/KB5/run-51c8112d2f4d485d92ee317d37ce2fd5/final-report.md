# Tóm tắt điều hành

Bản quét trên target `local`, commit `0ca3b9611524e2c3af39267a42a60944b9be2329`, ghi nhận **8 phát hiện, tất cả ở trạng thái `unresolved`**. Gate đang `pending`.

Trong đó có **4 phát hiện mức critical** (CWE-78 ×2, CWE-89 ×2) và **4 phát hiện mức high** (CWE-22 ×2, CWE-918 ×2). Không có phát hiện nào được xác nhận hay bác bỏ: validator ghi nhận "Insufficient independent evidence" cho cả 8 trường hợp.

Đối chiếu model vs scanner: `agreed: 0`, `model_only: 8`, `scanner_only: 0`. Toàn bộ phát hiện đến từ model, không có phát hiện nào scanner độc lập trùng khớp.

# Phạm vi và phương pháp

- Phạm vi: target `local`, commit `0ca3b9611524e2c3af39267a42a60944b9be2329`.
- Số phát hiện trong dữ liệu: 8. Dữ liệu cung cấp là mẫu phát hiện (8 trên 8), không kèm nội dung mã nguồn hay bằng chứng khai thác.
- Số mục bị lược khỏi model input: 0.
- Đối chiếu model vs scanner: `agreed: 0`, `model_only: 8`, `scanner_only: 0`.
- Kết luận của validator cho từng phát hiện: "Insufficient independent evidence. Scanner detections, model proposals and incomplete procedures do not establish confirmation or rejection." Nghĩa là chưa có bằng chứng độc lập để xác nhận hoặc bác bỏ; đề xuất của model không tự nó là bằng chứng khai thác.
- Chi tiết đầy đủ nằm trong scan exports. Những thông tin không có trong dữ liệu được cung cấp -- ví dụ khả năng khai thác thực tế, đầu vào cụ thể, hoặc lý do scanner không phát hiện -- được ghi là **unknown**, không suy đoán.
- Chi tiết đối chiếu và OWASP do ứng dụng hiển thị, không lặp lại ở đây.

# Phát hiện ưu tiên

**Critical (4)**

| ID | Mô tả | CWE | Vị trí | Trạng thái |
|---|---|---|---|---|
| model-fbf3e4d0e1409477 | OS command injection trong `Ping` qua tham số truy vấn `host` không được làm sạch | CWE-78 | `pkg/vuln_cmd.go:8` | unresolved |
| model-0d4a9028a16f4875 | SQL injection trong `FindUser` qua tham số `id` nối chuỗi | CWE-89 | `pkg/vuln_sql.go:8` | unresolved |
| model-3f9eee46eb25ec41 | OS command injection qua đối số không được làm sạch trong thực thi lệnh | CWE-78 | `pkg/vuln_cmd.go:1` | unresolved |
| model-8c671a93f622fe0b | SQL injection qua truy vấn nối chuỗi | CWE-89 | `pkg/vuln_sql.go:1` | unresolved |

**High (4)**

| ID | Mô tả | CWE | Vị trí | Trạng thái |
|---|---|---|---|---|
| model-7ed6498e602fa2bd | Path traversal trong `ReadDoc` qua tham số truy vấn `file` | CWE-22 | `pkg/vuln_path.go:8` | unresolved |
| model-6c2842ca30463621 | Server-side request forgery trong `Proxy` qua tham số truy vấn `url` | CWE-918 | `pkg/vuln_ssrf.go:5` | unresolved |
| model-bcb606f907353c3b | Path traversal trong việc dựng đường dẫn truy cập tệp | CWE-22 | `pkg/vuln_path.go:1` | unresolved |
| model-fdfb6598df3e153e | Server-side request forgery qua URL do kẻ tấn công kiểm soát | CWE-918 | `pkg/vuln_ssrf.go:1` | unresolved |

Cả 8 phát hiện đều do model đề xuất (`model_only`) và chưa có bằng chứng độc lập. Mức độ khai thác thực tế: **unknown**.

# Kết luận và bước tiếp theo

Gate đang `pending`; chưa có phát hiện nào được xác nhận hay xử lý. Các bước tiếp theo đề xuất:

1. Kiểm chứng thủ công từng phát hiện tại đúng vị trí đã nêu (`pkg/vuln_cmd.go:1` và `:8`, `pkg/vuln_sql.go:1` và `:8`, `pkg/vuln_path.go:1` và `:8`, `pkg/vuln_ssrf.go:1` và `:5`), đối chiếu với mã nguồn tại commit `0ca3b9611524e2c3af39267a42a60944b9be2329`.
2. Bổ sung bằng chứng độc lập (ví dụ đầu vào kiểm thử, luồng dữ liệu từ nguồn đến điểm nguy hiểm) để chuyển trạng thái từ `unresolved` sang xác nhận hoặc bác bỏ.
3. Xem scan exports để lấy chi tiết đầy đủ trước khi ra quyết định cho gate.

Cho đến khi có bằng chứng đó, trạng thái của cả 8 phát hiện giữ nguyên là `unresolved`.

## Đối chiếu model vs scanner

- Nhất trí (cả model và scanner đều thấy): 0
- Chỉ model thấy (scanner bỏ sót, cần người xem lại): 8
  - OS command injection in Ping via unsanitized 'host' query parameter @ pkg/vuln_cmd.go:8
  - Path traversal in ReadDoc via 'file' query parameter @ pkg/vuln_path.go:8
  - SQL injection in FindUser via string-concatenated 'id' parameter @ pkg/vuln_sql.go:8
  - Server-side request forgery in Proxy via 'url' query parameter @ pkg/vuln_ssrf.go:5
  - OS command injection via unsanitized argument in command execution @ pkg/vuln_cmd.go:1
  - SQL injection via string-concatenated query @ pkg/vuln_sql.go:1
  - Path traversal in file access path construction @ pkg/vuln_path.go:1
  - Server-side request forgery via attacker-controlled URL @ pkg/vuln_ssrf.go:1
- Chỉ scanner thấy (model không liệt kê): 0

Luồng model-only: nhất trí 0, chỉ model thấy 8 (chờ người xem lại trong hunt.json, chưa thành finding chính thức khi thiếu evidence), chỉ scanner thấy 0.

## OWASP Top 10:2025 and CWE mapping

This is a CWE classification of reported findings, not a coverage or compliance assessment. An empty category means No mapped findings reported; it does not mean tested, safe or passed. Counts retain finding status; pending includes unprocessed, triaged, assessed and pending validation. A finding with multiple labels may appear in several rows/categories; do not add those row counts.

| OWASP category | Reported CWE | Finding IDs | Finding status counts |
|---|---|---|---|
| A01:2025 Broken Access Control | CWE-22 | model-7ed6498e602fa2bd, model-bcb606f907353c3b | Confirmed: 0; Rejected: 0; Unresolved: 2; Pending: 0 |
| A01:2025 Broken Access Control | CWE-918 | model-6c2842ca30463621, model-fdfb6598df3e153e | Confirmed: 0; Rejected: 0; Unresolved: 2; Pending: 0 |
| A02:2025 Security Misconfiguration | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A03:2025 Software Supply Chain Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A04:2025 Cryptographic Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A05:2025 Injection | CWE-78 | model-3f9eee46eb25ec41, model-fbf3e4d0e1409477 | Confirmed: 0; Rejected: 0; Unresolved: 2; Pending: 0 |
| A05:2025 Injection | CWE-89 | model-0d4a9028a16f4875, model-8c671a93f622fe0b | Confirmed: 0; Rejected: 0; Unresolved: 2; Pending: 0 |
| A06:2025 Insecure Design | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A07:2025 Authentication Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A08:2025 Software or Data Integrity Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A09:2025 Security Logging &amp; Alerting Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A10:2025 Mishandling of Exceptional Conditions | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |

Mapping source: [OWASP Top 10:2025](https://top10.owasp.org/2025/); offline snapshot 2026-11-04.
