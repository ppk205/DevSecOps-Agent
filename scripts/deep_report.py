import json, glob
from pathlib import Path
from collections import Counter
SRC = ('.java', '.jsp', '.js', '.jsx', '.ts', '.tsx', '.py', '.php', '.vue')

def rel(p):
    p = (p or '').replace(chr(92), '/')
    return p.split('bench-repos/')[-1].split('/', 1)[-1] if 'bench-repos/' in p else p

def inscope(p):
    pl = p.lower()
    return pl.endswith(SRC) and '/.github/' not in pl

base = Path('artifacts/deep-compare')
rows = []
for slug in ['problem-spring-web', 'thelounge', 'vue-mdc', 'falcon', 'pikachu']:
    d = base / slug
    man = json.loads((d / 'manifest.json').read_text(encoding='utf-8'))
    rundir = Path(glob.glob(str(d / 'mine' / 'run-*'))[0])
    exp = sorted(rundir.glob('export-*.json'))
    mine = set()
    mrules = Counter()
    for o in json.loads(exp[0].read_text(encoding='utf-8'))['findings']:
        for ob in o.get('observations', []):
            loc = ob.get('location', {})
            mine.add((loc.get('file_path', ''), loc.get('line_start', 0)))
        mrules['%s [%s]' % (o.get('provenance', '?'), o.get('cwe_category', '?'))] += 1
    ext = {}
    sf = d / 'external' / 'semgrep-auto.json'
    if sf.exists():
        s = set()
        sx = set()
        for r in json.loads(sf.read_text(encoding='utf-8')).get('results', []):
            k = (rel(r.get('path', '')), (r.get('start') or {}).get('line', 0))
            (s if inscope(k[0]) else sx).add(k)
        ext['semgrep-auto'] = s
        ext['semgrep-auto-outscope'] = sx
    bf = d / 'external' / 'bandit.json'
    if bf.exists():
        bmed = set()
        for r in json.loads(bf.read_text(encoding='utf-8')).get('results', []):
            if r.get('issue_severity') in ('MEDIUM', 'HIGH'):
                bmed.add((rel(r.get('filename', '')), r.get('line_number', 0)))
        ext['bandit-med+'] = bmed
    nf = d / 'external' / 'njsscan.json'
    if nf.exists():
        n = set()
        for sec in ('nodejs', 'templates'):
            for rule, v in (json.loads(nf.read_text(encoding='utf-8')).get(sec, {}) or {}).items():
                for f in (v.get('files', []) if isinstance(v, dict) else []):
                    for ln in (f.get('match_lines', []) or [0]):
                        n.add((rel(f.get('file_path', '')), ln if isinstance(ln, int) else 0))
        ext['njsscan'] = n
    L = ['# Deep-scan: ' + slug, '',
         'Nguon: ' + man['url'] + ' @ `' + man['commit'][:12] + '` (' + man['lang'] + ')',
         'App tui: scan-run --profile full, mine_exit=%s, gate=failed (co finding la dung).' % man.get('mine_exit'),
         'Exports day du: sarif/json/html/md/txt/docx/final-report trong mine/run-*/', '',
         '## Mine: %d dong co finding' % len(mine),
         'Top CWE: ' + ', '.join(k + ' x' + str(v) for k, v in mrules.most_common(8)), '']
    L.append('| Doi thu | Trong scope source | Giao voi mine | Ngoai scope |')
    L.append('|---|---|---|---|')
    for k in ('semgrep-auto', 'bandit-med+', 'njsscan'):
        if k in ext:
            extra = ''
            if k == 'semgrep-auto':
                extra = '%d (yaml/CI/test)' % len(ext['semgrep-auto-outscope'])
            L.append('| %s | %d | %d | %s |' % (k, len(ext[k]), len(mine & ext[k]), extra))
    L += ['', 'Giao tinh tren scope source chung. Semgrep-auto quet rong hon (yaml/CI) la dung vai tro, khong phai loi.',
          'Chi tiet tung finding: mine/run-*/export-*.json|html|docx, external/*.json (raw).']
    (d / 'DEEP-COMPARE.md').write_text(chr(10).join(L), encoding='utf-8')
    rows.append({'repo': slug, 'lang': man['lang'], 'mine': len(mine),
                 'semgrep_auto': len(ext.get('semgrep-auto', set())),
                 'semgrep_auto_ov': len(mine & ext.get('semgrep-auto', set())),
                 'semgrep_auto_out': len(ext.get('semgrep-auto-outscope', set())),
                 'bandit_med': len(ext.get('bandit-med+', set())),
                 'bandit_med_ov': len(mine & ext.get('bandit-med+', set())),
                 'njsscan': len(ext.get('njsscan', set())),
                 'njsscan_ov': len(mine & ext.get('njsscan', set()))})
(base / 'DEEP-SUMMARY.json').write_text(json.dumps(rows, indent=2), encoding='utf-8')
R = ['# Deep-scan app-tui vs 3 app-ngoai, 5 web (moi ngon ngu 1)', '',
     'Mine = scan-run --profile full (deterministic + Laya, khong AI).',
     'Ext = semgrep --config auto + bandit + njsscan. Giao tinh tren scope source chung.', '',
     '| Repo | Lang | Mine | Semgrep-auto (giao / ngoai-scope) | Bandit Med+ (giao) | njsscan (giao) |',
     '|---|---|---|---|---|---|']
for r in rows:
    R.append('| %s | %s | %d | %d (%d / %d) | %s | %s |' % (
        r['repo'], r['lang'], r['mine'], r['semgrep_auto'], r['semgrep_auto_ov'], r['semgrep_auto_out'],
        ('%d (%d)' % (r['bandit_med'], r['bandit_med_ov']) if r['lang'] == 'Python' else '-'),
        ('%d (%d)' % (r['njsscan'], r['njsscan_ov']) if r['lang'] in ('JavaScript', 'TypeScript') else '-')))
(base / 'DEEP-REPORT.md').write_text(chr(10).join(R), encoding='utf-8')
print(chr(10).join(R))
