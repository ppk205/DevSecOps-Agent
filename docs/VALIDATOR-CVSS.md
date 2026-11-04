# Independent validation and CVSS v4.0

This guide describes the FR-50/53 correction. Finding status, numerical scoring
and verification of source assumptions are separate decisions.

## Status decisions

`IndependentValidator` consumes evidence and emits a retained decision. It does
not turn model confidence or scanner detections into independent proof. Current
scanner/model review records are explicitly marked non-independent. A model may
propose confirmed or rejected while the actual finding remains unresolved.
Human review controls remain available.

| Input | Decision effect |
| --- | --- |
| Model proposal or raw scanner observations | No terminal decision authority |
| Enough independently checked supporting records, or a qualifying completed demonstration | Can confirm, subject to scope/conflict checks |
| Strong independently checked counterevidence | Can reject when independent support does not conflict |
| Independent support and counterevidence, or conflicting duplicate IDs | Unresolved |
| Blocked, failed, inconclusive or incomplete procedure | Cannot confirm |
| A result from the fixed variant | Does not confirm/reject the original finding |
| Foreign finding/run or repeated evidence identity | Cannot inflate support |

Independent evidence metadata is reserved for trusted application verification
producers, after their checks actually succeed:

```json
{
  "independently_verified": true,
  "polarity": "supporting",
  "run_id": "the-matching-run",
  "verifier": "the-trusted-checker"
}
```

`polarity` is `supporting` or `contradicting`. Evidence records also need an
applicable kind, strength and source location/artifact reference. EvidenceRecord
uses metadata for its run identity; VerificationObservation has its own required
`run_id`. Verification observations must demonstrate the checked property on the
original vulnerable variant, complete legitimate-functionality checks, and
record an applicable procedure/version and independent producer. Model and
documentation records never become authoritative by claiming these flags.

These flags are provenance from trusted producers, not a permission the model
can request. The scanner/model adapter does not copy them from target content or
model responses. The validator checks their structure and scope; it cannot prove
that an external producer's assertions are truthful or implement that producer's
semantic checks. A general independent source verifier remains unimplemented.
FR-51/52/54 and semantic verification of CVSS assumptions remain implementation
gaps. Do not mark a raw detection independently verified to obtain a terminal label.

Decision metadata records policy `independent-evidence/2`, run/assessment IDs,
qualified support/counterevidence, verification IDs/outcomes, conflicting IDs and
ignored-record reasons. `evidence_refs` retains scoped inputs for the audit trail;
the qualified lists state which inputs affected the decision. Evidence-only
confirmation does not invent a runtime execution result. Historical decisions
and archived reports are preserved and are not recertified by this correction.

## CVSS arithmetic

The previous implementation used an older-style formula under a v4.0 label.
It has been replaced with FIRST's MacroVector lookup and interpolation method.
The bundled data and implementation are attributed under BSD-2-Clause; see
`src/vulnscan/assessment/CVSS4-LICENSE.txt`.

The parser validates metric order, duplicate/unknown metrics and values. A
complete v4.0 vector requires these eleven Base metrics, in order:

```text
AV / AC / AT / PR / UI / VC / VI / VA / SC / SI / SA
```

`UI:A` is valid Active interaction. `AT` accepts N/P. The v3 Scope values U/H
are not valid v4 values: v4 `S` is Supplemental Safety and accepts X/N/P.
Threat, Environmental and Supplemental values/order are validated. Supplemental
metrics do not alter the numerical score. Standard defaults for optional metrics
are applied according to FIRST; missing mandatory Base metrics are not filled in.

Public functions remain in `assessment/cvss.py`:

- `parse_vector(vector)`: parse valid tokens in order; a partial Base vector can
  be parsed for diagnostics.
- `validate(vector)`: return syntax/value/order/missing-metric errors.
- `score(vector)`: compute a result for a complete vector. Partial Base input
  returns `base_score=None`, `qualitative=None` and missing metric names. Malformed
  tokens raise ValueError. A real zero score requires a valid complete vector.

`CVSSResult.base_score` always means CVSS-B. `overall_score` uses any supplied
Threat/Environmental metrics and `nomenclature` identifies CVSS-B, BT, BE or BTE.
The result carries separate qualitative ratings. For example, the following
illustrative vector scores Base 9.3; adding `E:P` gives CVSS-BT 8.9:

```text
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
```

Those are arithmetic results for the supplied vector, not findings or a claim
that its metrics apply to a particular application. Reference:
[FIRST specification](https://www.first.org/cvss/v4.0/specification-document),
[implementation guide](https://www.first.org/cvss/v4.0/implementation-guide) and
[reference calculator](https://github.com/FIRSTdotorg/cvss-v4-calculator).

## Pipeline and display

`CVSSAssessment` requires a complete valid vector. Construction and validated
assignment recompute numbers rather than accepting model-authored scores.
The bounded loop and single-shot fallback both use it. They retain model
assumptions as proposals and record `cvss_score_status` as computed, invalid or
not_provided, with safe validation errors. Structured JSON containing braces in
its rationale is decoded correctly. Model JSON extraction is bounded to 64
possible starts for malformed responses; it cannot execute target instructions.

Assessments retain Base/contextual scores and ratings, the group nomenclature,
`calculation_source="FIRST CVSS v4.0"`, and
`metric_assumptions_verified=False`. The existing application severity enum uses
`info` for the zero-score case; `base_rating="None"` retains FIRST's rating name.
Correct arithmetic does not change scanner severity, the finding status or a
policy gate. No independent verification of the chosen vector metrics is implied.

Review stores the assessment and decision in run results and finding metadata,
including JSON report exports. Native AI execution reaches the same code over
the owned Python bridge. A parsed explicit verdict no longer causes a redundant
single-shot call just because the extracted rationale omitted its JSON wrapper.

The dashboard finding view and live assessment feed label **Base** separately
from contextual scores such as **CVSS-BT**. They state that calculation does not
verify assumptions. Scores lacking calculation provenance are marked as legacy;
existing archived scores and historical status labels are not rewritten. Invalid
vectors remain unscored, with errors available in the assessment/finding detail.

The runtime scorer needs no `cvss` package, Node runtime or network lookup. Node
was used only to execute FIRST's pinned reference during verification. The
already installed optional `cvss` package was an additional comparison, not a new
runtime dependency. No dependency manifest or lockfile changed.

## Verification limits

The corrected implementation matched FIRST's pinned JavaScript on every one of
104,976 Base combinations and 5,000 deterministic extended samples, with zero
mismatches. The 5,000 samples are not exhaustive for the extended space. The
installed optional `cvss` 3.6 package matched all 15 retained reference cases.
These comparisons establish arithmetic conformance for those inputs; they do
not establish vulnerability accuracy or metric applicability to source.

The [verification record](VALIDATOR-CVSS-VERIFICATION-2026-11-04.md) lists executed
checks, retained evidence, remaining repository failures and untested platforms.
