#!/usr/bin/env python3
"""Score SAST results on OWASP Benchmark suites, with one rule for every tool.

Rule: a case is flagged when the tool reports an accepted CWE in the case's own
file, the same file-level rule as OWASP BenchmarkUtils. Other CWEs count neither
way. "strict" accepts only the CWE in the answer key. "normalized" also accepts
the near-equivalents in EQUIV, applied identically to all tools.
Usage: score_owasp.py <results_dir> <out.json>
"""
import csv
import glob
import json
import os
import re
import sys
from collections import defaultdict

NAME = re.compile(r"BenchmarkTest\d{5}")
EQUIV = {"327": {"326", "327"}, "328": {"327", "328"}, "94": {"94", "95"}}
SUITES = {"BenchmarkJava": "expectedresults-1.2.csv", "BenchmarkPython": "expectedresults-0.1.csv"}


def load_cases(suite):
    path = os.path.expanduser(f"~/scan-targets/{suite}/{SUITES[suite]}")
    return {
        r[0].strip(): (r[1].strip(), r[2].strip() == "true", r[3].strip())
        for r in csv.reader(open(path, encoding="utf-8"))
        if r and not r[0].lstrip().startswith("#")
    }


def nums(value):
    if isinstance(value, list):
        return {c for item in value for c in nums(item)}
    return set(re.findall(r"(?:CWE-?)?(\d{2,4})", str(value), flags=re.I)[:1]) if value else set()


def read_native(results, suite):
    hits, tiers = defaultdict(set), defaultdict(lambda: defaultdict(set))
    path = glob.glob(f"{results}/{suite}-native/run-*/scanner-native-hunt.json")
    if not path:
        return None, None
    for o in json.load(open(path[0], encoding="utf-8")).get("observations", []):
        m = NAME.search((o.get("location") or {}).get("file_path", ""))
        if m:
            found = nums(o.get("cwe_category"))
            hits[m.group()] |= found
            tiers[str(o.get("confidence"))][m.group()] |= found
    return hits, tiers


def read_semgrep(path):
    if not os.path.exists(path):
        return None
    hits = defaultdict(set)
    for r in json.load(open(path, encoding="utf-8")).get("results", []):
        m = NAME.search(r.get("path", ""))
        if m:
            hits[m.group()] |= nums((r.get("extra", {}).get("metadata") or {}).get("cwe"))
    return hits


def read_sarif(path):
    if not os.path.exists(path):
        return None
    hits = defaultdict(set)
    for run in json.load(open(path, encoding="utf-8")).get("runs", []):
        tags = {}
        comps = [run["tool"]["driver"]] + run["tool"].get("extensions", [])
        for comp in comps:
            for rule in comp.get("rules", []):
                cw = {
                    t.split("cwe-")[-1].lstrip("0")
                    for t in (rule.get("properties") or {}).get("tags", [])
                    if "cwe-" in t.lower()
                }
                tags[rule["id"]] = cw
        for res in run.get("results", []):
            for loc in res.get("locations", []):
                m = NAME.search(loc["physicalLocation"]["artifactLocation"]["uri"])
                if m:
                    hits[m.group()] |= tags.get(res.get("ruleId"), set())
    return hits


def read_sonar(path):
    if not os.path.exists(path):
        return None
    hits = defaultdict(set)
    for item in json.load(open(path, encoding="utf-8")):
        m = NAME.search(item.get("file", ""))
        if m:
            hits[m.group()] |= {str(c) for c in item.get("cwe", [])}
    return hits


def metrics(c):
    tpr = c["tp"] / (c["tp"] + c["fn"]) if c["tp"] + c["fn"] else None
    fpr = c["fp"] / (c["fp"] + c["tn"]) if c["fp"] + c["tn"] else None
    prec = c["tp"] / (c["tp"] + c["fp"]) if c["tp"] + c["fp"] else None
    f1 = 2 * prec * tpr / (prec + tpr) if prec and tpr else None
    you = tpr - fpr if tpr is not None and fpr is not None else None
    out = dict(c)
    for k, v in (("tpr", tpr), ("fpr", fpr), ("precision", prec), ("f1", f1), ("youden", you)):
        out[k] = round(v, 4) if v is not None else None
    return out


def flagged(cases, hits, normalized):
    res = {}
    for name, (_, _, cwe) in cases.items():
        ok = EQUIV.get(cwe, {cwe}) if normalized else {cwe}
        res[name] = bool(hits.get(name, set()) & ok)
    return res


def score(cases, flags):
    cat = defaultdict(lambda: dict(tp=0, fp=0, fn=0, tn=0))
    for name, (category, vuln, _) in cases.items():
        key = ("tp" if flags[name] else "fn") if vuln else ("fp" if flags[name] else "tn")
        cat[category][key] += 1
    total = dict(tp=0, fp=0, fn=0, tn=0)
    for counts in cat.values():
        for k, v in counts.items():
            total[k] += v
    return {"total": metrics(total), "by_category": {k: metrics(v) for k, v in sorted(cat.items())}}


def main():
    results, out_path = sys.argv[1:3]
    report = {
        "rule": "accepted CWE reported in the case file; other CWEs ignored",
        "normalization": {k: sorted(v) for k, v in EQUIV.items()},
    }
    for suite in SUITES:
        cases = load_cases(suite)
        short = "java" if "Java" in suite else "py"
        tools = {}
        n_hits, tiers = read_native(results, suite)
        if n_hits is not None:
            tools["native-hunt"] = n_hits
        tools["semgrep-default"] = read_semgrep(f"{results}/{suite}-semgrep.json")
        tools["semgrep-default+audit"] = read_semgrep(f"{results}/{suite}-semgrep-audit.json")
        tools["codeql-security-extended"] = read_sarif(f"{results}/codeql/{short}.sarif")
        tools["sonarqube-community"] = read_sonar(f"{results}/sonar/{short}.json")
        tools = {k: v for k, v in tools.items() if v is not None}
        block = {"cases": len(cases), "vulnerable": sum(v[1] for v in cases.values()), "tools": {}}
        flags = {}
        for tool, hits in tools.items():
            strict = flagged(cases, hits, False)
            norm = flagged(cases, hits, True)
            flags[tool] = norm
            block["tools"][tool] = {"strict": score(cases, strict), "normalized": score(cases, norm)}
            s, n = block["tools"][tool]["strict"]["total"], block["tools"][tool]["normalized"]["total"]
            print(f"{suite:16}{tool:27} strict TPR {s['tpr']:.4f} FPR {s['fpr']:.4f} J {s['youden']:.4f} | norm TP {n['tp']} FP {n['fp']} FN {n['fn']} TN {n['tn']} TPR {n['tpr']:.4f} FPR {n['fpr']:.4f} P {n['precision']} F1 {n['f1']} J {n['youden']:.4f}")
        if tiers:
            block["native_by_confidence"] = {k: score(cases, flagged(cases, v, True))["total"] for k, v in sorted(tiers.items())}
            for k, v in block["native_by_confidence"].items():
                print("   native confidence", k, {x: v[x] for x in ("tp", "fp", "tpr", "fpr", "precision", "youden")})
        vuln = {k for k, v in cases.items() if v[1]}
        safe = {k for k, v in cases.items() if not v[1]}
        pairs = {}
        names = list(flags)
        if "native-hunt" in flags:
            for other in names[1:]:
                a, b = flags["native-hunt"], flags[other]
                pairs[other] = {
                    "tp_both": sum(a[k] and b[k] for k in vuln),
                    "tp_native_only": sum(a[k] and not b[k] for k in vuln),
                    "tp_other_only": sum(b[k] and not a[k] for k in vuln),
                    "tp_neither": sum(not a[k] and not b[k] for k in vuln),
                    "fp_native_only": sum(a[k] and not b[k] for k in safe),
                    "fp_other_only": sum(b[k] and not a[k] for k in safe),
                    "union": metrics(dict(
                        tp=sum(a[k] or b[k] for k in vuln), fn=sum(not (a[k] or b[k]) for k in vuln),
                        fp=sum(a[k] or b[k] for k in safe), tn=sum(not (a[k] or b[k]) for k in safe))),
                }
                print("   pair native vs", other, {k: v for k, v in pairs[other].items() if k != "union"}, "union J", pairs[other]["union"]["youden"])
        block["pairs_with_native"] = pairs
        print("   category normalized TPR/FPR:")
        cats = sorted(block["tools"][next(iter(block["tools"]))]["normalized"]["by_category"])
        for c in cats:
            row = []
            for tool in block["tools"]:
                v = block["tools"][tool]["normalized"]["by_category"][c]
                row.append(f"{tool.split('-')[0][:6]} {v['tpr']:.2f}/{v['fpr']:.2f}" if v["tpr"] is not None else f"{tool[:6]} -")
            print(f"     {c:15}", " | ".join(row))
        report[suite] = block
    json.dump(report, open(out_path, "w", encoding="utf-8"), indent=2)


if __name__ == "__main__":
    main()
