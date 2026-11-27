## Tóm tắt điều hành

Bản quét trên target `local`, commit `11debbf45287b0a4c283f01d7a64abfa1f10ac69`, có trạng thái gate `pending`. Kết quả ghi nhận 17 phát hiện: **10 `unresolved`** và **7 `unprocessed`**. Không có phát hiện nào ở trạng thái xác nhận hay phủ định.

Đối chiếu model với scanner: `agreed: 0`, `model_only: 17`, `scanner_only: 0`. Nghĩa là không có phát hiện nào được cả hai bên đồng thuận, và toàn bộ 17 phát hiện đều chỉ đến từ model.

Các nhóm vấn đề nổi bật trong 12 mẫu được cung cấp: thông tin xác thực bị gán cứng trong mã nguồn (CWE-798), pod Kubernetes chạy đặc quyền dưới quyền root, mount host path, và image nền không ghim phiên bản (`ubuntu:latest`). Mức nghiêm trọng trải từ critical đến medium. Với các mục `unresolved`, validator ghi: "Insufficient independent evidence. Scanner detections, model proposals and incomplete procedures do not establish confirmation or rejection."

## Phạm vi và phương pháp

- Target: `local`
- Commit: `11debbf45287b0a4c283f01d7a64abfa1f10ac69`
- Gate: `pending`
- Số lượng: 17 phát hiện, gồm 10 `unresolved` và 7 `unprocessed`
- Đối chiếu model vs scanner: `agreed: 0`, `model_only: 17`, `scanner_only: 0`
- Dữ liệu đầu vào chỉ chứa 12 trong 17 phát hiện; **5 phát hiện bị lược khỏi input**. Nội dung của 5 phát hiện này **không rõ** (unknown); chi tiết đầy đủ được ghi là có trong scan exports, nhưng các export đó không được cung cấp ở đây.
- Chỉ dùng các dữ kiện đã nêu. Không có thông tin nào khác về quy trình quét, công cụ, thời điểm hay phạm vi file được cung cấp, nên các điểm đó **không rõ**.
- Chi tiết đối chiếu (comparison) và OWASP do ứng dụng hiển thị, không được lặp lại trong bản tóm tắt này.

## Phát hiện ưu tiên

**Critical**

| ID | Tiêu đề | CWE | Trạng thái | Vị trí | Ghi chú validator |
|---|---|---|---|---|---|
| model-f2108583c9ef724e | Hardcoded GitHub Personal Access Token in C header | CWE-798 | unresolved | `src/vuln_secret.h:3` | Insufficient independent evidence |
| model-da52a917cd61585d | Privileged pod running as root | CWE-UNCLASSIFIED | unresolved | `deploy/vuln_pod.yaml:10` | Insufficient independent evidence |
| model-8d2763e75b3679a9 | Pod runs a privileged container as root with no restriction on privilege escalation | CWE-UNCLASSIFIED | unresolved | `deploy/vuln_pod.yaml:9` | Insufficient independent evidence |
| model-0cd0f4bb77912512 | Hardcoded credential committed in source header | CWE-798 | unprocessed | `src/vuln_secret.h:1` | Không có ghi chú validator trong dữ liệu cung cấp |

**High**

| ID | Tiêu đề | CWE | Trạng thái | Vị trí | Ghi chú validator |
|---|---|---|---|---|---|
| model-193a6e1b4a7207d0 | Container runs as root with a floating 'latest' base image | CWE-UNCLASSIFIED | unresolved | `docker/vuln/Dockerfile:2` | Insufficient independent evidence |
| model-8c8acb05feb5dc1e | Pod explicitly runs as UID 0 (root) without runAsNonRoot enforcement | CWE-UNCLASSIFIED | unresolved | `deploy/vuln_pod.yaml:11` | Insufficient independent evidence |
| model-3a12340615263d38 | Kubernetes pod runs privileged container | CWE-UNCLASSIFIED | unprocessed | `deploy/vuln_pod.yaml:1` | Không có ghi chú validator trong dữ liệu cung cấp |
| model-44d863545ff968a8 | Kubernetes pod mounts a host path | CWE-UNCLASSIFIED | unprocessed | `deploy/vuln_pod.yaml:1` | Không có ghi chú validator trong dữ liệu cung cấp |

**Medium**

| ID | Tiêu đề | CWE | Trạng thái | Vị trí | Ghi chú validator |
|---|---|---|---|---|---|
| model-f427f78550d5b550 | Service account token automounted in privileged root pod | CWE-UNCLASSIFIED | unresolved | `deploy/vuln_pod.yaml:5` | Insufficient independent evidence |
| model-b5e12cfc2239861f | Unpinned mutable base image ubuntu:latest in workload manifest | CWE-UNCLASSIFIED | unresolved | `deploy/vuln_pod.yaml:8` | Insufficient independent evidence |
| model-5325207d51d0ee12 | Unpinned ubuntu:latest base image with unbounded package install in build | CWE-UNCLASSIFIED | unresolved | `docker/vuln/Dockerfile:1` | Insufficient independent evidence |
| model-bc2851331ffa2b18 | Container image pinned to floating ubuntu:latest tag | CWE-UNCLASSIFIED | unresolved | `deploy/vuln_pod.yaml:8` | Insufficient independent evidence |

Ghi chú về các mục trùng chủ đề: các phát hiện liên quan đến thông tin xác thực gán cứng (`src/vuln_secret.h:1` và `src/vuln_secret.h:3`), pod đặc quyền/root (`deploy/vuln_pod.yaml:1`, `:9`, `:10`, `:11`), host path (`deploy/vuln_pod.yaml:1`), và `ubuntu:latest` (`docker/vuln/Dockerfile:1`, `docker/vuln/Dockerfile:2`, `deploy/vuln_pod.yaml:8` hai lần với hai ID khác nhau) được giữ nguyên thành từng mục riêng theo đúng vị trí dòng, không gộp hay khử trùng lặp.

Trong 7 mục `unprocessed` được cung cấp, 4 mục đã xuất hiện trong 12 mẫu trên (`model-0cd0f4bb77912512`, `model-3a12340615263d38`, `model-44d863545ff968a8`). Số còn lại của nhóm `unprocessed` nằm trong **5 phát hiện bị lược**, nên nội dung **không rõ**.

## Kết luận và bước tiếp theo

Chưa thể kết luận về tính đúng hay sai của bất kỳ phát hiện nào. Toàn bộ 17 phát hiện chỉ đến từ model (`model_only: 17`), không có phát hiện nào được scanner đồng thuận (`agreed: 0`) hay chỉ do scanner phát hiện (`scanner_only: 0`). Các mục `unresolved` chưa có bằng chứng độc lập theo đánh giá của validator; các mục `unprocessed` chưa có ghi chú validator trong dữ liệu được cung cấp. Gate đang ở trạng thái `pending`.

Bước tiếp theo dựa trên dữ kiện hiện có:

1. Xử lý 7 phát hiện `unprocessed`, gồm việc lấy chi tiết của các mục nằm trong 5 phát hiện bị lược từ scan exports.
2. Thu thập bằng chứng độc lập cho 10 phát hiện `unresolved`, tập trung vào các vị trí cụ thể: `src/vuln_secret.h:1`, `src/vuln_secret.h:3`, `deploy/vuln_pod.yaml:5`, `:8`, `:9`, `:10`, `:11`, `docker/vuln/Dockerfile:1`, `docker/vuln/Dockerfile:2`.
3. Chờ gate chuyển khỏi trạng thái `pending`; chưa có thông tin về điều kiện để gate hoàn tất, nên phần này **không rõ**.

## Đối chiếu model vs scanner

- Nhất trí (cả model và scanner đều thấy): 0
- Chỉ model thấy (scanner bỏ sót, cần người xem lại): 17
  - Hardcoded GitHub Personal Access Token in C header @ src/vuln_secret.h:3
  - Container runs as root with a floating 'latest' base image @ docker/vuln/Dockerfile:2
  - Privileged pod running as root @ deploy/vuln_pod.yaml:10
  - Service account token automounted in privileged root pod @ deploy/vuln_pod.yaml:5
  - Pod explicitly runs as UID 0 (root) without runAsNonRoot enforcement @ deploy/vuln_pod.yaml:11
  - Unpinned mutable base image ubuntu:latest in workload manifest @ deploy/vuln_pod.yaml:8
  - Unpinned ubuntu:latest base image with unbounded package install in build @ docker/vuln/Dockerfile:1
  - Pod runs a privileged container as root with no restriction on privilege escalation @ deploy/vuln_pod.yaml:9
  - Container image pinned to floating ubuntu:latest tag @ deploy/vuln_pod.yaml:8
  - Dockerfile builds from unpinned base image ubuntu:latest @ docker/vuln/Dockerfile:1
  - Dockerfile installs packages without pinning versions or cleaning the apt cache @ docker/vuln/Dockerfile:3
  - Container command hands out an interactive root shell @ docker/vuln/Dockerfile:4
  - Hardcoded credential committed in source header @ src/vuln_secret.h:1
  - Kubernetes pod runs privileged container @ deploy/vuln_pod.yaml:1
  - Kubernetes pod mounts a host path @ deploy/vuln_pod.yaml:1
  - Container image runs as root @ docker/vuln/Dockerfile:1
  - Unpinned mutable base image tag in build @ docker/vuln/Dockerfile:1
- Chỉ scanner thấy (model không liệt kê): 0

Luồng model-only: nhất trí 0, chỉ model thấy 17 (chờ người xem lại trong hunt.json, chưa thành finding chính thức khi thiếu evidence), chỉ scanner thấy 0.

## OWASP Top 10:2025 and CWE mapping

This is a CWE classification of reported findings, not a coverage or compliance assessment. An empty category means No mapped findings reported; it does not mean tested, safe or passed. Counts retain finding status; pending includes unprocessed, triaged, assessed and pending validation. A finding with multiple labels may appear in several rows/categories; do not add those row counts.

| OWASP category | Reported CWE | Finding IDs | Finding status counts |
|---|---|---|---|
| A01:2025 Broken Access Control | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A02:2025 Security Misconfiguration | CWE-489 | model-929c8c665efebadc | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 1 |
| A03:2025 Software Supply Chain Failures | CWE-1104 | model-8ea3d70b0681fe22, model-ec789c1ecd33430d | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 2 |
| A04:2025 Cryptographic Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A05:2025 Injection | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A06:2025 Insecure Design | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A07:2025 Authentication Failures | CWE-798 | model-0cd0f4bb77912512, model-f2108583c9ef724e | Confirmed: 0; Rejected: 0; Unresolved: 1; Pending: 1 |
| A08:2025 Software or Data Integrity Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A09:2025 Security Logging &amp; Alerting Failures | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| A10:2025 Mishandling of Exceptional Conditions | — | — | Confirmed: 0; Rejected: 0; Unresolved: 0; Pending: 0 |
| Unmapped (unclassified_cwe) | CWE-UNCLASSIFIED | model-158337abf744790d, model-193a6e1b4a7207d0, model-3a12340615263d38, model-44d863545ff968a8, model-5325207d51d0ee12, model-8c8acb05feb5dc1e, model-8d2763e75b3679a9, model-a20b7eee948ed43a, model-b5e12cfc2239861f, model-bc2851331ffa2b18, model-da52a917cd61585d, model-f427f78550d5b550 | Confirmed: 0; Rejected: 0; Unresolved: 9; Pending: 3 |

Mapping source: [OWASP Top 10:2025](https://top10.owasp.org/2025/); offline snapshot 2026-11-04.
