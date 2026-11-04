#!/bin/bash
REPO="/mnt/d/phuc/Code Project/DevSecOps-Agent"; BIN="$REPO/.venv-linux/bin"; OUT=~/scan-results/owasp-2026-11-04; cd "$OUT" || exit 1
for pair in "BenchmarkJava p/java" "BenchmarkPython p/python"; do set -- $pair; t=$1; p=$2
 s=$(date +%s); "$BIN/semgrep" scan --config "$p" --config p/security-audit --metrics=off --json --quiet --timeout 30 --output "$t-semgrep-audit.json" ~/scan-targets/$t >/dev/null 2>"$t-semgrep-audit.stderr"; echo "semgrep+audit $t exit=$? sec=$(( $(date +%s)-s ))"
done
python3 - <<'PY'
import json,glob,csv,re,collections
for t,cs in (('BenchmarkJava','expectedresults-1.2.csv'),('BenchmarkPython','expectedresults-0.1.csv')):
    import os
    cases={r[0]:(r[1],r[2],r[3]) for r in csv.reader(open(os.path.expanduser(f'~/scan-targets/{t}/{cs}'))) if r and not r[0].startswith('#')}
    for suffix in ('semgrep','semgrep-audit'):
        d=json.load(open(f'{t}-{suffix}.json'))
        c=collections.defaultdict(collections.Counter)
        for r in d['results']:
            m=re.search(r'BenchmarkTest\d{5}',r['path'])
            if not m: continue
            cat=cases[m.group()][0]; meta=r['extra'].get('metadata') or {}
            for x in (meta.get('cwe') if isinstance(meta.get('cwe'),list) else [meta.get('cwe')]):
                c[cat][re.sub(r'[: ].*','',str(x))]+=1
        print(t,suffix,len(d['results']),'errs',len(d.get('errors',[])))
        for k,v in sorted(c.items()): print('  ',k,cases and next(x[2] for x in cases.values() if x[0]==k),v.most_common(4))
    s=json.load(open(glob.glob(f'{t}-native/run-*/scanner-native-hunt.json')[0])); print(' native duration_ms',s['duration_ms'],'units',s['eligible_units'],s['analyzed_units'],s['coverage_percent'])
PY
