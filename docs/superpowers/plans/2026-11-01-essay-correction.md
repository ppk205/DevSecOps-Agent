# Essay correction for the human-gated architecture — Plan

> **For agentic workers:** REQUIRED SUB-SKILLS:
> - `vietnamese-technical-writing` for every sentence written;
> - `anthropic-skills:docx` for reading and writing the `.docx`;
> - `dataviz` before drawing any data chart;
> - the Playwright MCP tools (`mcp__plugin_playwright_playwright__browser_*`) for screenshots.
>
> Steps use checkbox (`- [ ]`) syntax. AGENTS D4 and D5 apply: the essay is the owner's document, phases start only when the owner asks, and **the first page is never modified**.

**Goal:** Correct `essay/DeCuongChiTiet_v6_HinhMoi.docx` for the architecture as built: a hand-written harness, then any model provider, then gated tools, then Laya, then finding cards, then a fix proposal, with a human deciding at every gate.

**Owner rules (2026-11-02):**

| Part | Treatment |
|---|---|
| First page | Never modified (D5). |
| Mở đầu | Submitted. **Required edits only** (M1–M5, X). |
| Chương 1 | **Headings and numbers unchanged.** Content is deepened where the lecturer requirements demand it (§2b): vulnerability depth and exploitation, concrete techniques, and AI described as a supporting tool in the current app. Everything else stays. |
| Chương 2, Chương 3 | **Headings and section numbers stay exactly as in v6.** The content under each heading is rewritten heavily. No section is added, removed, renamed or renumbered. |
| Chương 4, Kết luận, Phụ lục | Written only after the experiment produces data. |

## 0. Lecturer requirements (`special_requirements.txt`): these take priority

Every phase must satisfy these. Where a requirement conflicts with an architecture or spec wording, the essay follows the requirement.

**Framing rule, from requirements 8–10 and 22:**
- **What is studied:** the object of study is *security vulnerabilities in the source code of Java Servlet/JSP web applications*: their detection and their severity classification.
- **AI is a supporting tool, never the main object.** Every chapter goes in the order object, then detection techniques and tools, then AI.
- **How detection is described:**
  1. Static analysis (the harness's source–sink rules and route lookup, plus the baseline tools) finds candidates.
  2. AI supports the investigation, the explanation, the CVSS vector proposal and the fix proposal.
  3. Laya narrows the work.
  4. A human decides at every gate.

  This matches the code: the model reads only batches of candidates that the static tools surfaced.
- **Wording to avoid:** "AI là lõi" (AI is the core), "mô hình là bộ quét chính" (the model is the main scanner). Spec §10 and decision D10 were updated to match on 2026-11-02.

| # | Requirement (short) | Where satisfied | Status |
|---|---|---|---|
| 1 | Topic: a system that detects vulnerabilities and classifies severity | Ch.1 1.3; Ch.2 2.8.6 (CVSS computed from the vector, confirmed by a human); Ch.3 3.9 (CVSS error) | ✓ planned |
| 2–4 | Specific object: the application (characteristics, structure), its vulnerabilities, the standards (lifecycle, types), detection techniques and process | Ch.1 1.1–1.4 in v6 (unchanged) | ✓ in v6 |
| 5 | Tools and techniques that detect it, in Ch.2 | Ch.2 2.1–2.6 (survey kept) | ✓ |
| 6 | Ch.3 states what the experiment involves (application, language, tools, source storage, vulnerabilities, environment) | v6 Ch.3 headings already list these (3.2, 3.2.2, 3.5, 3.6, 3.3, 3.4). Headings kept; content rewritten. Ch.3 must not turn into a system-design chapter (design stays in Ch.2). | ✓ |
| 7 | After the experiment: results, evaluation, comparison with existing tools, completeness | Ch.4 headings 4.4 and 4.6 exist | ✗ **blocked**: no plan yet for running the experiment (see the open decision below) |
| 8–10 | Object first, then tools, then AI; AI is only a supporting tool, but explain clearly how it is used | Framing rule above; M1 and M4 rewritten to keep "AI chỉ hỗ trợ" (AI only assists) | ✓ after the fix |
| 12, 18 | Each vulnerability type: the weakness it comes from, OWASP Top 10, how it is exploited, in depth | v6 1.2.3–1.2.7 name CWEs per class, but exploitation is thin: the word "khai thác" (exploit) appears 0 times in 1.2.5–1.2.7, and there are few code examples. **Owner decided 2026-11-02: deepen Ch.1** (§2b, items V1–V6). | ✓ planned |
| 14 (techniques) | "Các kỹ thuật … đang rất chung chung" (the techniques are too general) | §2b, items T1–T3: a worked taint example, how each static technique works, how dynamic analysis works | ✓ planned |
| 13 | Title unchanged; Java web in scope and limitations | First page untouched (D5); Mở đầu 4 and 5 | ✓ |
| 14 | Level of the group's own AI use and its control; simple, technical style | Mở đầu §6 has a "nhóm sử dụng AI" (how the group uses AI) part; `vietnamese-technical-writing` | ⚠ M4 must check that the disclosure matches reality (see below) |
| 15 | The compared tools are limited | B1–B7, a closed list (§4, 3.5.4) | ✓ |
| 16 | Which tools static analysis uses | Ch.2 2.8.2 (harness rules), 2.8.3 (baselines) | ✓ |
| 17 | How dynamic analysis works | Ch.1 1.4.4, Ch.2 2.5 explain it; Ch.3 3.8.3 states it is not built | ✓ (stated as a limitation) |
| 19 | Level of Agentic AI in the app and how it is controlled | **New table** in 2.8.4: current autonomy level (proposes a patch; a human approves it on a separate branch) mapped to gates G0–G7 and the tool limits | ✓ after the fix |
| 21 | Detection and its connection to the AI agent made clearer | 2.8.2 → 2.8.4 with D1, D3, D4 (candidates → Laya → batch → model) | ✓ |
| 22 | Basic trial: feed in a program, find vulnerabilities (static or dynamic), then use AI to help | **New in 3.8.5:** a basic trial on `tests/fixtures/java/vulnerable` and `safe`: (1) static results from the harness rules and the baselines (CI evidence in `evidence/ci-testsuite/`); (2) a harness session on the same program, showing what AI adds (explanation, CVSS vector, fix). Needs a model, like T1. | ⚠ needs a model run |

**Open decisions for the owner:**
- **(a) Requirement 12/18.** Decided on 2026-11-02: deepen Ch.1 (§2b).
- **(b) Requirement 7.** Plan written on 2026-11-02: `docs/superpowers/plans/2026-11-02-experiment.md`. Its outputs feed:
  - Ch.3 3.8.5 (the basic trial);
  - Ch.4 4.1–4.6 (`tables.md`, `metrics.json`);
  - Ch.4 4.4 (the comparison with Copilot Autofix and Semgrep);
  - Ch.4 4.7 (the IRIS comparison, from `experiment/related-work.md`).

  Original wording of this decision: Approve writing a separate experiment plan: ground truth labelling and running B1–B7 / S1–S3. Without it, Ch.4 cannot be written.
- **(c) Requirement 14.** Mở đầu §6 says AI was used for "gợi ý mã và rà soát mã" (suggesting and reviewing code). If AI coding agents wrote large parts of the system, the sentence must say so, together with the controls (AGENTS.md rules, tests, human review). Only the owner can confirm the true extent.

**Approach:**
- Chương 2 already holds the design (2.7 requirements, 2.8.1–2.8.7 design), so the new architecture is described **there**, inside the existing headings.
- Chương 3 describes the experiment run on that system, also inside its existing headings.
- Mở đầu and Chương 1 receive version qualifiers and forward references to Mục 2.8 where a sentence would otherwise be false.
- Figures come from four sources:
  - real application screenshots (Playwright);
  - terminal captures;
  - architecture diagrams;
  - data charts drawn from `evidence/`.

**Output:** `essay/DeCuongChiTiet_v9_KienTrucMoi.docx`. v6 is never overwritten, and v7 and v8 hold other content. New images go to `essay/images/v9/`, together with a `MANIFEST.md`.

**Source of truth for content:**
- `docs/ARCHITECTURE-MODIFICATION.md`, with §8 for the experiment, §10 for essay corrections and §13 for what is implemented;
- `docs/superpowers/specs/2026-11-01-chat-client-remote-triggers-design.md`;
- the code on `main` on the day a phase runs.

## Global Constraints

- **D5:** the first page is byte-identical in v9. Checked after every phase.
- **Headings in Chương 2 and 3:** the heading text, level and order are identical to v6. Checked after every phase.
- **Figure and table numbers** may shift inside Chương 2–3 when a figure is added or dropped. Word's caption fields renumber them. Every reference to a moved number anywhere in the essay is updated.
- **D4:** essay files change only when the owner asks for a phase. Each phase writes v9, then stops for review.
- **E1 and D2:** describe only what runs on `main` on the day of writing. The Go chat TUI, the web remote and local triggers are labelled *"định hướng, chưa triển khai"* (planned, not yet built) until their PRs merge. Version 0.3.0 is described in the past tense, as the predecessor.
- **E2:** every number is computed by a script from `evidence/`, `.devsec/` or a command output, never typed in. Placeholders such as "(cần số liệu)" (needs data) stay until real data exists.
- **E4 and E5:**
  - CVSS scores come from `score_cvss4`.
  - Model and scanner output is *"đề xuất"* (proposed) or *"cảnh báo"* (alert), never *"lỗ hổng đã xác nhận"* (confirmed vulnerability).
- **E7:** never write into `evidence/`. Screenshots that need the database use a copy in the scratchpad.
- **Style:** `vietnamese-technical-writing`. Short sentences, one idea per sentence, no filler. Keep v6 terminology.

## 1. Measurement of v6 (2026-11-01, parsed from `word/document.xml`)

| Item | Count |
|---|---|
| Words / headings | 31,610 / 130 |
| Figures / tables (captions) | 23 / 26 |
| Chương 2 / Chương 3 words | about 8.8k / about 6.4k |
| Sentences or table rows matching old-architecture phrases* | Mở đầu 14 · Chương 1 16 · Chương 2 40 · Chương 3 20 · lists 5 |
| Empty headings | Chương 4 (9 sections), Kết luận (3), Phụ lục (4) |

\* The phrases searched for:
- "bốn công cụ" (four tools)
- "tất định" (deterministic)
- "chỉ hỗ trợ" (only assists)
- "chưa nối" (not wired up)
- "mặc định tắt" (off by default)
- "chỉ đọc" (read-only)
- "không ghi tệp" (writes no files)
- `agent/tools.py`
- "Không cho phép" (not allowed)
- "bộ kiểm chứng" / "kiểm chứng độc lập" / validator (the validator)
- "0.3.0"

Phase 0 saves the list as `essay_old_arch_sentences.json` in the session scratchpad.

## 2. Mở đầu: required edits only

A sentence changes only if one of these holds:
- **(a)** it is false for the version it names;
- **(b)** it states a timeless fact about "hệ thống" (the system) that is no longer true;
- **(c)** it contradicts the rewritten Chương 2–3;
- **(d)** it refers to a figure or table number that moved.

Make the smallest fix that works, in this order of preference:
1. A version qualifier of at most 6 words.
2. A forward reference "(Mục 2.8)".
3. Replacing a clause.
4. Rewriting the sentence.

Style and content otherwise stay unchanged.

| # | Where | Current (short) | Edit |
|---|---|---|---|
| M1 | Mở đầu 2. Mục tiêu (goals) | AI "chỉ hỗ trợ" phân tích ngữ cảnh (AI only assists context analysis) | **Keep "AI chỉ hỗ trợ"** (requirement 10). Change only the mechanism: static analysis finds candidates, AI supports the investigation, a human decides at every gate, and the surveyed tools are the comparison baselines. |
| M2 | Mở đầu 3. Câu hỏi và giả thuyết (research questions) | Q1/H1 "thêm lớp hỗ trợ Agentic AI sau chuỗi công cụ tất định" (add an Agentic AI layer after the deterministic tool chain) | Restate Q1/H1 as harness (S1/S2) against baselines (B1–B7). Add Q2–Q3 from spec §10 as a short list: Laya's effect, human decisions per scan, fix acceptance. They must match Bảng 3.1. |
| M3 | Mở đầu 4. Phạm vi (scope) | "hệ thống chỉ dùng phân tích tĩnh, gồm bốn công cụ" (the system uses only static analysis, with four tools) | Replace the clause, following spec §10 row "§4". Add one sentence: code stays on the machine only with a local model; a cloud model needs consent (G0). |
| M4 | Mở đầu 6. Mức độ dùng AI (level of AI use) | "AI chỉ hỗ trợ, còn quyền quyết định thuộc về luật cố định" (AI only assists; fixed rules decide); "năm công cụ chỉ đọc, tối đa 5 lượt" (five read-only tools, at most 5 turns) | Keep "AI chỉ hỗ trợ". Replace "luật cố định" (fixed rules) with "con người tại các cổng G0–G7" (a human at gates G0–G7). Update the tool facts (12 tools; writing only after G6, in a separate worktree; the budget) and point to Mục 2.8.4. Group AI-use paragraph: edit only after the owner answers decision (c) in §0. |
| M5 | Mở đầu 9. Bố cục (outline) | the chapter summaries | Edit only a summary sentence that becomes false. The chapter titles do not change. |
| X | Mở đầu and Chương 1 | references to Hình/Bảng 1.x, 2.x and 3.x | Update the numbers that shift (§2b–4). A script lists them all. |

Estimated size: about 10 sentences. No paragraph is rewritten beyond M1–M4.

## 2b. Chương 1: same headings, content deepened for the lecturer requirements

Headings, levels and numbers stay as in v6. The chapter keeps its order: the application, then its vulnerabilities, then the standards, then detection techniques, then AI as a supporting tool. Paragraphs that already meet the requirements stay unchanged.

**CWE set to cover.** Chương 1 must explain every CWE that the experiment uses. That set is the union of:
- the CWEs already in v6 Ch.1: 22, 78, 79, 89, 327, 330, 434, 502, 611, 639, 798, 862, 918, 1395;
- the harness rule CWEs not yet in Ch.1: **200, 306, 601**;
- any extra CWE in Bảng 3.4.

Before writing, a script prints this union. Every CWE in it gets a block below.

**The block for each CWE.** These are prose paragraphs inside the existing subsection, with no new headings, about 120–180 words plus code:
1. **Điểm yếu gốc** (root weakness): the CWE and its parent class, and why it appears in Servlet/JSP code (which API, which habit).
2. **Cách khai thác** (how it is exploited): the attacker's steps, and the input sent, as a short request or payload.
3. **Mã lỗi và mã an toàn** (vulnerable and safe code): two Java/JSP snippets of at most 8 lines each, in the style of JVA-bookstore. No real project secrets.
4. **Dấu hiệu khi phân tích tĩnh** (static analysis signal): the source, the sink, and the missing check, plus which harness rule or baseline tool detects it (named only if it really does).
5. **Hậu quả và mức nghiêm trọng** (impact and severity): the impact in one sentence, plus an example CVSS v4.0 base vector. The **score is computed with `score_cvss4` and printed by a script**, never typed in.

| # | Section (unchanged) | v6 words | Add or change | Est. words added |
|---|---|---|---|---|
| V1 | 1.2.1 Điểm yếu, lỗ hổng, khai thác và vòng đời (weakness, vulnerability, exploit, lifecycle) | 474 | Keep. Add one sentence linking weakness (CWE), then vulnerability (an instance in code), then exploit, then CVE and CVSS, as the frame used in V2–V6. | 60 |
| V2 | 1.2.3 Nhóm lỗi tiêm (A05): injection | 969 | Complete the blocks for CWE-89, 78 and 79. Split XSS into reflected and stored, and say where the JSP output sinks are. Add exploitation steps where they are missing. | 350 |
| V3 | 1.2.4 Kiểm soát truy cập (A01): access control | 647 | Blocks for CWE-862, 639, 22 and 918. **Add CWE-601** (open redirect) and **CWE-200** (information exposure), which are both harness rules and A01. | 700 |
| V4 | 1.2.5 Lỗi mật mã và xác thực (A04, A07): cryptography and authentication | 513 | Blocks for CWE-327, 330 and 798. **Add CWE-306** (missing authentication for a critical function, A07). | 550 |
| V5 | 1.2.6 Dữ liệu có cấu trúc và tệp tải lên (A02, A06, A08): structured data and uploads | 514 | Blocks for CWE-611, 434 and 502. Each with exploitation steps (an external entity, a JSP web shell upload, a gadget chain), described conceptually, without a working exploit chain. | 450 |
| V6 | 1.2.7 Thư viện và chuỗi cung ứng (A03): libraries and supply chain | 357 | The CWE-1395 block. One **real** CVE example taken verbatim from `evidence/jva-fullscan-2026-11-01/**/scanner-owasp-dependency-check.json` (its id, library and score exactly as recorded), and how a vulnerable library is reached from application code. | 250 |
| T1 | 1.4.1 Biểu diễn mã nguồn và phân tích nhiễm bẩn (code representation, taint analysis) | 334 | A worked taint example on one short servlet: source `getParameter`, then propagation, then a sanitizer or none, then the sink. One small D-style figure is allowed (§5.3 rules). | 250 |
| T2 | 1.4.2 Phân tích tĩnh (static analysis) | 647 | Make it concrete: how a pattern rule, a semantic or data-flow query, and bytecode analysis each match the V2 example. Static analysis in the system means the harness's source–sink rules and route lookup. **The four tools become the comparison baselines.** Bảng 1.6 body and caption: "công cụ đối chứng" (baseline tools). | 250 |
| T3 | 1.4.4 Phân tích động (dynamic analysis) | 636 | How dynamic testing works step by step: crawl, then inject a payload, then observe the response, then confirm. What IAST adds. Why the system does not run it (requirement 17), stated as a limitation. | 150 |
| T4 | 1.4.6 Quy trình (process) | 266 | The process, with the system as it is now: static candidates, then Laya, then AI-supported investigation, then a human decision, then the report. **Hình 1.5 stays** if it is generic; otherwise relabel it under the §5.3 rules. | 100 |
| A1 | 1.5 opening, 1.5.1 | 322 | AI is a **supporting tool** (D10). The harness's static tools detect. The model investigates, explains and proposes, and a human decides. Remove "việc phát hiện do bốn công cụ đảm nhận" (detection is done by the four tools). | rewrite ~150 |
| A2 | 1.5.2 Giới hạn ngữ cảnh, ảo giác (context limits, hallucination) | 303 | Keep. Add how the system limits hallucination: `check_citations` (file:line, exact code), "unknown" never meaning "safe", the human decides at G5. | 80 |
| A3 | 1.5.3 Mức độ tự chủ của AI (AI autonomy levels) | 397 | Update **Bảng 1.9** to the current app. Insert the level "Đề xuất bản vá, người duyệt áp dụng trên nhánh riêng" (proposes a patch; a human approves it on a separate branch) between level 2 and level 3. The system sits at that level. Level 3 (AI merges or decides by itself) stays forbidden. Laya is on and advisory. | rewrite ~200 |
| A4 | 1.5.4 Cơ chế kiểm soát tác tử (agent controls) | 346 | Update **Bảng 1.10** to the current controls: gates G0–G7 (G0 and G6 always human, G5 human-only); path confinement and credential exclusion; `<untrusted_code>` wrapping; key redaction; writes only after G6, in a worktree; budget; audit log. The detailed mechanism is in Mục 2.8.4 and 2.8.7. | rewrite ~200 |
| A5 | 1.6 Tổng quan nghiên cứu liên quan (related work) | 304 | Add 1–2 verified sources on LLM-assisted vulnerability detection with human oversight, positioned as support for static analysis. Only sources that can actually be opened and checked. | 120 |
| A6 | 1.7 Kết luận chương 1 (chapter conclusion) | 273 | Restate: the object, then the techniques, then AI as a support tool with human control. | rewrite ~250 |

Estimated size: Chương 1 grows from about 11.6k to about 15k words. About 3.4k words are added and about 1k rewritten. Code snippets are extra.

Safety: the exploitation text explains mechanisms and example inputs at textbook level, of the kind found in the OWASP and CWE pages. It contains no working exploit chain or weaponized payload.

## 3. Chương 2: same headings, heavy content

The survey (2.1–2.6) keeps its facts about each tool and is reframed as the selection of baselines. The design (2.7–2.8) is rewritten to describe the harness on `main`.

The "Fig/table slots" column lists v6's numbering, mapped to the new content. D and P IDs are defined in §5.

| Heading (unchanged) | v6 words | Treatment | New content | Fig/table slots |
|---|---|---|---|---|
| CHƯƠNG 2 (opening) | 128 | rewrite | The design describes the harness at the commit on `main`. 0.3.0 is named as the predecessor (deterministic scanners, AI not wired up). | — |
| 2.1 Tiêu chí lựa chọn và đánh giá công cụ | 371 | edit | The criteria now serve two uses: choosing baselines, and what the harness's own tools must cover. | Bảng 2.1: keep, add one column if needed |
| 2.2, 2.2.1, 2.2.2 | ~1.4k | light edit | Keep the facts. Each tool's paragraph ends with its baseline role (B1–B3). | — |
| 2.2.3 Phạm vi bao phủ và giới hạn | 332 | edit | Coverage gaps motivate the harness tools (source–sink rules, route lookup). | Hình 2.1: caption "...công cụ đối chứng" (baseline tools) |
| 2.3, 2.3.1–2.3.3 | ~1.2k | light edit | Keep. B4 and B5 roles. Update the "phiên bản 0.3.0 chưa …" (version 0.3.0 does not yet …) sentences to the current state. | — |
| 2.4 Công cụ và kỹ thuật ứng dụng AI | 399 | heavy | Position the hand-written harness against AI scanning products and agent frameworks (AGENTS A1 explains why). Human gates as the difference. | — |
| 2.5 Công cụ kiểm thử động | 305 | light edit | Keep. Dynamic verification stays "chưa triển khai" (not built). | — |
| 2.6 Đánh giá tổng hợp và khoảng trống | 583 | heavy | Gaps K1–K6 mapped to the **new** components: harness, gates, Laya triage, citation check, CVSS from code, fix worktree. | Bảng 2.2: keep. Hình 2.2 and 2.3: redraw with the new component names |
| 2.7 Yêu cầu chức năng và phi chức năng | 427 | heavy | Functional: session, tools, gates G0–G7, provider choice, finding card, fix proposal, report. Non-functional: path confinement, credential exclusion, redaction, local-model option, full audit log, budget. | Bảng 2.3: redo (gap → requirement → component) |
| 2.8.1 Kiến trúc tổng thể và luồng xử lý kho mã nguồn | 509 | heavy | Overview: human, client, harness, model, tools, target. The session loop. The gate flow and the ask/auto modes. Component status at the commit. | Hình 2.4 → **D1** (overview). Hình 2.5 → **D2** (gate flow). Bảng 2.4: redo (status at commit). **New** gate table G0–G7. |
| 2.8.2 Nhận diện dự án, tiền xử lý và lập bản đồ source và sink | 473 | heavy | `inventory`, `extract_candidates` (sink rules, routes), `lookup_route` (servlet/filter mapping), `Workspace.resolve` confinement, `<untrusted_code>` wrapping. | **New** D3 (four tool groups). **New** tool registry table. |
| 2.8.3 Quét bằng tổ hợp công cụ phân tích tĩnh và phụ thuộc | 410 | heavy | This becomes the **baseline arm**: `scan-run` (Semgrep, SpotBugs/FindSecBugs, Dependency-Check, Gitleaks in Docker) and B7 (`scan-run` model paths with cloud consent). The harness never calls them (A4), and the model never sees their results. | — |
| 2.8.4 Vai trò điều phối của Agentic AI và tập công cụ cung cấp | 703 | heavy | The model's tool-call loop. The provider layer (profiles, two transports, redaction, budget, G0 for cloud). Laya runs before investigation, is advisory, and runs on CPU. Its route shapes the batch. | Hình 2.6 (Laya probabilities): keep. Hình 2.7 → **D4** (Laya in the flow). **New** D5 (provider layer). **New** provider profile table. **New** table "Mức tự chủ của AI và cơ chế kiểm soát" (AI autonomy level and controls, requirement 19). It reuses the levels of Bảng 1.9, plus the current level "đề xuất bản vá, người duyệt áp dụng trên nhánh riêng" (proposes a patch; a human approves it on a separate branch), and maps each control to a gate or tool limit. |
| 2.8.5 Hợp nhất, khử trùng lặp và sàng lọc dương tính giả | 559 | heavy | How the candidate list narrows: dedup key, Laya route, the human choice at G3, a token budget per batch. Model investigation reads only the batch. False positives are rejected at G5. | Hình 2.8 → candidate narrowing (labels only, no numbers). Hình 2.9: **dropped** (it showed a 0.3.0 trial artifact). |
| 2.8.6 Phân loại CWE và ước lượng điểm CVSS v4.0 kèm lập luận | 425 | heavy | The CWE comes from the sink rule or the model's proposal. The model proposes a CVSS v4.0 vector; the score is computed by `score_cvss4` (`cvss` 3.6) and is never typed in. The human confirms. | Bảng 2.5 (tool severity mapping): keep, retitled as baseline normalisation |
| 2.8.7 Kiểm chứng lỗ hổng và sinh bằng chứng | 371 | heavy | `check_citations` (file:line, exact code), the finding card, G5 human-only status, the fix proposal, G6, the `devsec/fix-*` worktree, re-scan, G7. The report keeps the decision log. | Hình 2.10 → **D6** (card and G5). **New** D7 (fix flow). |
| 2.9 Kết luận chương 2 | 284 | rewrite | Restate. | — |

Estimated size: Chương 2 grows from about 8.8k to about 10k words, with about 5k rewritten. Figures go from 10 to 12 (one dropped, three added). Tables go from 5 to 8.

## 4. Chương 3: same headings, heavy content

| Heading (unchanged) | v6 words | Treatment | New content | Fig/table slots |
|---|---|---|---|---|
| CHƯƠNG 3 (opening) | 90 | rewrite | The experiment compares the harness (S1–S3) with the baselines (B1–B7) on JVA-bookstore. | — |
| 3.1 Mục tiêu và phạm vi thực nghiệm | 429 | heavy | The research questions from M2. Configurations. Scope: JVA-bookstore at `dd48d12`. | Bảng 3.1: redo (question × configuration × metric) |
| 3.2.1–3.2.3 Ứng dụng web mục tiêu | ~0.8k | keep | — | Hình 3.1–3.2, Bảng 3.2–3.3: keep |
| 3.3.1 Danh mục CWE và ánh xạ OWASP | 328 | edit | The "luật phát hiện" (detection rule) column becomes harness rule plus baseline rule. | Bảng 3.4: change the column |
| 3.3.2 Nguồn gốc và phân bố mẫu | 394 | edit | Real counts only. | Bảng 3.5: fill when data exists |
| 3.4 Môi trường thực nghiệm: phần cứng, thời gian chạy và Docker cách ly | 287 | heavy | Windows host; WSL Kali with Docker for the baselines; GTX 1650 4 GB, with Laya on CPU (A7); local versus cloud providers; measured run times from `evidence/` (computed by script). | Bảng 3.6: redo |
| 3.5.1 Công cụ phân tích tĩnh và bộ luật cho Java | 137 | heavy | Baseline versions pinned in `ci/scanners.Dockerfile`, the locks and `.venv-linux`. The harness's own sink rules, by count and class. | Bảng 3.7: redo |
| 3.5.2 Công cụ phân tích phụ thuộc và phát hiện bí mật lộ lọt | 162 | edit | B4 and B5 configuration, and the NVD cache reuse. | — |
| 3.5.3 Mô hình ngôn ngữ, tham số sinh và cấu trúc lời nhắc | 194 | heavy | The models used, as added models (alias, base URL, protocol, model id). They are added like in Hermes: the key belongs to the added model and never appears in the essay. The structure of `SYSTEM_PROMPT`. Untrusted wrapping. Budget. Cost read from session logs only. | Bảng 3.8: redo |
| 3.5.4 Nhóm đối chứng | 190 | heavy | B1–B7 and S1–S3 defined (spec §8). | Hình 3.3 → **D8** (matrix). Bảng 3.9: redo. P2, P5 if available. |
| 3.6.1 Kho lưu trữ, mã phiên bản và cấu trúc lưu kết quả | 258 | heavy | The `evidence/` layout; `.devsec/sessions`, `reports`, `worktrees`; SARIF; CI artifacts. | Hình 3.4 → **D9** (tree). Hình 3.5: keep. |
| 3.6.2 Cơ chế bảo đảm tính tái lập | 234 | heavy | Commit pinning, `uv.lock`, SHA-pinned actions, session JSONL and `--resume`, the Laya config, the provider and model recorded per session. | — |
| 3.7.1–3.7.3 Tập nhãn chuẩn (ground truth) | ~0.7k | light edit | Laya mentions become advisory only. The human label is final. | Hình 3.6–3.7: keep |
| 3.8.1 Các bước thực hiện và thứ tự chạy công cụ | 200 | heavy | Numbered session procedure: G0 → plan → scan → Laya → select → investigate → card → G5 → fix → G7. What is logged at each step. Baselines run separately. | T1 (console session) if available |
| 3.8.2 Kiểm chứng bằng khả năng tiếp cận | 177 | heavy | Reachability through `lookup_route` and the citation hops. Function-level tests remain planned. | — |
| 3.8.3 Kiểm chứng động trong sandbox | 108 | edit | State plainly: not built. | — |
| 3.8.4 Số lần lặp và xử lý kết quả không ổn định | 167 | heavy | Model nondeterminism: repetitions per configuration and provider, and how disagreement between runs is reported. | — |
| 3.8.5 Kết quả các lần chạy thử | 373 | heavy | **(1) Basic trial** (requirement 22): the small programs `tests/fixtures/java/vulnerable` and `safe`, first with static analysis only (harness rules, plus the baseline results in `evidence/ci-testsuite/`), then with a harness session, showing what AI adds. **(2)** The 2026-11-01 JVA-bookstore baseline runs, without and with Laya, labelled **baseline**. All numbers computed from `evidence/`. | Bảng 3.10: redo (adds a basic-trial row). **New** C1–C4. **New** P1, P3, P4, P6; T1 from the basic-trial session. |
| 3.9 Chỉ số đánh giá | 540 | heavy | Precision, Recall, F1, FPR and CVSS error. Added: Laya's token and time reduction, human decisions and minutes per gate, fix acceptance and re-scan pass rate, provider comparison. | Bảng 3.11: redo |
| 3.10 Nguyên tắc an toàn và đạo đức | 339 | heavy | G0 before code leaves the machine. Writes only after G6, in a worktree. Untrusted code and prompt injection. Redaction. Credential exclusion. Authorised target only. | — |
| 3.11 Kết luận chương 3 | 214 | rewrite | Restate. | — |

Estimated size: Chương 3 grows from about 6.4k to about 8.5k words, with about 5.5k rewritten. Figures go from 7 to 7 plus up to 9 screenshots and charts.

## 5. Images

### 5.1 Kinds and tools

| Kind | Tool | Used for |
|---|---|---|
| **P** — application screenshot | Playwright MCP (`browser_navigate`, `browser_resize`, `browser_take_screenshot`) | web UI, HTML reports |
| **T** — terminal capture | run the real command → capture text (or a Go `View()` golden) → convert ANSI to HTML with `rich` (already installed through `textual`) → Playwright screenshot | `devsec chat` console, Go chat TUI |
| **D** — architecture diagram | `essay/figures/build_figures.py` helpers (`box`, `diamond`, `chip`, `arrow`, `legend`, `svg`) → headless Chrome PNG, the same renderer and style as v6 | design figures |
| **C** — data chart | a small script reading `evidence/**/summary.json` → SVG bars with the same helpers (no new dependency) | trial-run numbers |

### 5.2 Real application screenshots (P, T)

Capture rules:
- Web pages use a 1440×900 viewport. Use an element crop when only one panel matters.
- Use the app's own theme, without modifying the app for the essay.
- Data comes from a **copy** of `evidence/jva-fullscan-2026-11-01/vulnscan.db` in the scratchpad, served on 127.0.0.1.
- Check that no key value, token or home path is visible. Crop or re-capture if one is.
- Each image gets a row in `essay/images/v9/MANIFEST.md`: file, URL or command, `git rev-parse HEAD`, data source, viewport, and time.
- Never mock a screen. If a feature is not built, its slot holds "(hình bổ sung khi tính năng được triển khai)" (figure added when the feature is built) until it is.

| ID | Screen | How | Data | Available when | Placed in |
|---|---|---|---|---|---|
| P1 | PIT WALL home: run list | `/app/` | DB copy | project 1 merged | 3.8.5 |
| P2 | New scan form with the cloud-consent checkbox | `/app/scans/new` | — | project 1 merged | 3.5.4 |
| P3 | Live pipeline of a completed run | `/app/live` (run `e209adbb…`) | DB copy | project 1 merged | 3.8.5 |
| P4 | Findings table and detail drawer with the Laya route | `/app/findings` | DB copy | project 1 merged | 3.8.5 |
| P5 | Model-vs-scanner comparison | `/app/reports` | DB copy | project 1 merged | 3.5.4 |
| P6 | HTML report export | `file:///…/run-e209adbbf1b64049a21533ea92e537b6/export-88b3956e5047.html` | evidence (read-only) | **now** | 3.8.5 |
| T1 | `devsec chat` console: G0, tool calls, G3 | a real session on JVA-bookstore | needs a local model or an owner-provided key | **now**, if a model is available | 3.8.1 |
| T2 | Go chat TUI: start screen; chat with tool blocks; G6 dialog with diff | `View()` golden → HTML | a real or recorded session | project 2 merged | 2.8.1 or 3.8.1 |
| T3 | Web remote session with a gate dialog | `/app/remote` | live session | project 3 merged | 3.8.1 |
| T4 | Pending-review banner after a commit | TUI or web | a scratch clone with the hook | project 4 merged | 3.8.1 |

The GitHub Actions pages for the saved CI runs return 404 (checked 2026-11-01). CI evidence uses Hình 3.5 and the artifact files.

### 5.3 Diagram style: simple but rich

The structure carries the detail. The words stay short.

1. **Labels:** at most 4 words. Use a noun phrase, never a sentence.
2. **No notes on nodes.** Explanations go in the paragraph before the figure.
3. **Edge labels:** 1–2 words, such as "gọi" (call), "trả kết quả" (return result), "phê duyệt" (approve) or "từ chối" (reject).
4. **Detail comes from structure:**
   - swimlanes by actor (Người dùng | Giao diện | Harness | Mô hình | Công cụ & Laya | Kho mã đích — user, interface, harness, model, tools and Laya, target repository);
   - grouping boxes;
   - numbered steps ①–⑨, explained in the body text;
   - small chips for lists (tool names, routes, profiles).
5. **Fixed shape vocabulary**, with a legend on every figure:
   - rounded box = component;
   - cylinder = storage;
   - diamond = gate;
   - **red diamond** = dangerous gate (G0, G6);
   - dashed grey = planned or not yet built.
6. **Color only encodes category.** At most 4 colors plus grey, from the existing `C` palette in `build_figures.py`.
7. **At most about 15 nodes per figure.** If there are more, split into an overview and a zoomed figure.
8. **Size:** the v6 width `W` and font (Times New Roman). Text must stay readable at 16 cm wide in Word.
9. **Caption:** one line, "Hình x.y. <noun phrase>".

Per-figure check: every label ≤ 4 words, a legend is present, the node count is ≤ 15, planned parts are dashed, and the figure matches the code on the day it is drawn.

### 5.4 Diagram list (D)

The labels are fixed here so that no figure invents wording.

| ID | Caption (draft) | Nodes (labels) | Key edges | Slot |
|---|---|---|---|---|
| D1 | Tổng quan kiến trúc hệ thống (system architecture overview) | Người dùng · Giao diện (console; TUI, web dashed until built) · Harness · Nhật ký phiên · Mô hình (chips: Anthropic, OpenAI, DeepSeek, Ollama…) · Công cụ harness · Laya · Kho mã đích · Worktree sửa lỗi · Công cụ đối chứng (grey, outside the box, "chỉ so sánh" — comparison only) | ① yêu cầu (request) ② gọi mô hình (call model) ③ gọi công cụ (call tool) ④ phân loại (triage) ⑤ hỏi cổng (ask gate) ⑥ quyết định (decide) ⑦ báo cáo (report) | Hình 2.4 |
| D2 | Luồng phiên và cổng G0–G7 (session flow and gates) | G0 Đồng ý phiên (session consent) → G1 Kế hoạch quét (scan plan) → G2 Quét, Laya (scan, Laya) → G3 Chọn ứng viên (choose candidates) → G4 Điều tra (investigate) → G5 Kết luận (conclusion) → G6 Áp bản vá (apply fix) → G7 Quét lại (re-scan). Mode chips ask/auto. G0 and G6 red. G5 "chỉ người" (human only). | approve / reject / edit as short branch labels | Hình 2.5 |
| D3 | Bốn nhóm công cụ của harness (the harness's four tool groups) | Groups:<br>• Quét (scan): propose_scan_plan, inventory, extract_candidates<br>• Phân loại (triage): laya_triage, select_candidates, begin_investigation<br>• Điều tra (investigate): read_file, grep, lookup_route<br>• Kết luận và sửa (conclude and fix): propose_finding, propose_fix, rescan<br>These are the 12 names in `schemas()` in `harness/tools.py` (checked 2026-11-02). Re-check before drawing. | gate badges on chips | new, 2.8.2 |
| D4 | Laya trước bước điều tra (Laya before investigation) | Ứng viên (candidates) → Laya (CPU) → route chips (human_review, low_priority, authorization_analysis …) → G3 Người chọn (human chooses) → Lô điều tra (investigation batch) | "gợi ý" (suggests); "không đổi trạng thái" (does not change status) | Hình 2.7 |
| D5 | Lớp nhà cung cấp mô hình (model provider layer) | Hồ sơ (profile) → Giao thức (protocol) → Bộ truyền (transport: Anthropic Messages; Chat Completions) → Nhà cung cấp (provider). Chips: Ngân sách (budget), Che khóa (key redaction), Nhật ký (log). Cloud and local lanes, with G0 on the cloud lane. | — | new, 2.8.4 |
| — | Thu hẹp danh sách ứng viên (narrowing the candidate list) | Trích ứng viên (extract candidates) → Khử trùng lặp (deduplicate) → Tuyến Laya (Laya route) → G3 → Lô điều tra (batch) → G5 bác bỏ (reject at G5). Labels only, no counts. | — | Hình 2.8 |
| D6 | Thẻ phát hiện và quyết định G5 (finding card and the G5 decision) | CWE · Đường đi source→sink (path, hops with file:line) · Kiểm trích dẫn (citation check) · Vector CVSS → Điểm (code) · Đề xuất (proposed) → G5 → confirmed / rejected / need_more | — | Hình 2.10 |
| D7 | Đề xuất và áp dụng bản vá (fix proposal and application) | Đề xuất bản vá (fix proposal) → G6 (red) → Nhánh devsec/fix-* (branch) → Worktree → Quét lại (re-scan) → G7 → còn / hết (still present / gone). The dashed "Tệp .patch" (.patch file) alternative appears only once project 4 has merged. | — | new, 2.8.7 |
| D8 | Cấu hình đối chứng và thử nghiệm (baseline and experimental configurations) | A matrix: rows B1–B7 and S1–S3; columns Semgrep, SpotBugs, CodeQL, Dependency-Check, Gitleaks, Mô hình (model), Công cụ harness (harness tools), Laya, Cổng (gates). Cells are dots only. | — | Hình 3.3 |
| D9 | Thư mục kết quả và nhật ký (results and logs folders) | A tree: `evidence/<target>-<kind>-<date>/run-*/{summary.json, scanner-*.json, export-*}` and `.devsec/{sessions, reports, worktrees}` | — | Hình 3.4 |

Redraw Hình 2.2 and 2.3 (gap → component) with the new component names, under the same style rules.

### 5.5 Data charts (C)

Follow the `dataviz` skill:
- horizontal bars with direct value labels;
- one accent color plus grey;
- no 3D;
- a source line under each chart, e.g. *"Nguồn: evidence/jva-fullscan-2026-11-01/run-4c67…/summary.json"*.

The script prints the numbers it read, and that printout is saved in MANIFEST.

| ID | Chart | Source | Slot |
|---|---|---|---|
| C1 | Raw findings per baseline tool | `run-4c67cbbda9cf49479fa9520f40c86bbe/summary.json` | 3.8.5 |
| C2 | Findings by severity | same | 3.8.5 |
| C3 | Laya routes | `run-e209adbbf1b64049a21533ea92e537b6/summary.json` | 3.8.5 |
| C4 | Run time: total, NVD download, Laya (CPU) | both summaries and `scan-stdout.log` / `scan-laya-stdout.log` | 3.4 or 3.8.5 |

## 6. Phases

Each phase starts on the owner's request and ends with v9 plus a change list for review.

- [ ] **Phase 0: prerequisites** (no essay change).
  - Save the old-phrase list and the v6 heading list for Chương 2–3.
  - Copy `vulnscan.db` into the scratchpad.
  - Ask the owner about a model for T1.
  - Check whether project 1 has merged, which P1–P5 need.
- [ ] **Phase 1a: Chương 1 vulnerability and technique depth** (§2b, V1–V6 and T1–T3). This is independent of the architecture, so it can run first.
- [ ] **Phase 1b: Chương 2 text** (§3).
- [ ] **Phase 1c: Chương 1 AI and process parts** (§2b, T4 and A1–A6), after Phase 1b, because they point into Mục 2.8.
- [ ] **Phase 2: Chương 3 text** (§4).
- [ ] **Phase 3: images.**
  - Draw D1–D9, the redrawn Hình 2.2, 2.3 and 2.8, and C1–C4.
  - Capture the P and T images that are available, and fill MANIFEST.
- [ ] **Phase 4: required edits in Mở đầu** (M1–M5, X). Then regenerate the lists of figures, tables and abbreviations.
- [ ] **Phase 5: later screenshots** as projects 2–4 merge. Update the "định hướng" (planned) labels.
- [ ] **Phase 6: Chương 4, Kết luận, Phụ lục**, after the experiment produces `evidence/<target>-experiment-YYYY-MM-DD/`.
- [ ] **Phase 7: consistency pass.**
  - Every claim matches `main` (E1).
  - Every number has a source (E2).
  - Every cross-reference resolves.

## 7. Checks after every phase

All scripts run in the scratchpad.

1. **First page unchanged (D5).** The XML before the first page or section break is identical between v6 and v9.
2. **Headings unchanged in Chương 1–3.** The list of (level, text) pairs is identical between v6 and v9.
3. **Mở đầu minimal, Chương 1 traceable.**
   - In Mở đầu, every changed paragraph maps to an item M1–M5 or X.
   - In Chương 1, every changed paragraph maps to an item V1–V6, T1–T4 or A1–A6.
   - Anything else is reverted.
   - The CWE union printed in Phase 1a is fully covered.
4. **Old-architecture phrases.**
   - Chương 2–3 have 0 hits, except in sentences explicitly about 0.3.0 or baselines.
   - In Mở đầu and Chương 1, each hit names 0.3.0 or is on the unchanged list.
5. **Numbers.** Every number in changed text and in the charts is listed with its source file. Unsourced numbers block the phase.
6. **Images.** Every image has a MANIFEST row. Every diagram passes the §5.3 check. No secrets or home paths are visible.
7. **Lecturer requirements.**
   - Every row of the §0 table touched by the phase is re-checked and its status updated.
   - A search for "AI là lõi" (AI is the core), "bộ quét chính" (main scanner) and "đối tượng nghiên cứu là AI" (AI is the object of study) returns 0 hits.
8. **Owner review.** The owner reviews the change list before the next phase starts.
