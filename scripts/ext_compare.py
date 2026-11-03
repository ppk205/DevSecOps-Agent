"""App-vs-app: DevSecOps-Agent (deterministic lane) vs external scanners.

External apps (standalone, vendor defaults):
  - Semgrep OSS with DEFAULT registry rulesets (p/<lang>) — different rules
    from the app's 85 custom rules.
  - Bandit (Python), njsscan (JS/TS).
My app result = union of native-hunt + semgrep(custom) + gitleaks from the
existing bench JSONs (same repos, same commits).
Output: artifacts/bench-compare/<slug>/external/*.json + EXT-COMPARE.md.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

PACK = {'Java': 'p/java', 'JavaScript': 'p/javascript',
        'TypeScript': 'p/typescript', 'Python': 'p/python', 'PHP': 'p/php'}
REPOS = Path('D:/dev/bench-repos')
BASE = Path('artifacts/bench-compare')
SEMGREP = '.venv/Scripts/semgrep.exe'
BANDIT = '.venv/Scripts/bandit.exe'
NJSSCAN = '.venv/Scripts/njsscan.exe'


def run(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr[-300:]
    except subprocess.TimeoutExpired:
        return 124, '', 'TIMEOUT'


def main() -> None:
    rows = json.loads((BASE / 'SUMMARY.json').read_text(encoding='utf-8'))
    summary = []
    for row in rows:
        slug, lang = row['repo'], row['lang']
        d = BASE / slug
        ext = d / 'external'
        ext.mkdir(exist_ok=True)
        repo = str(REPOS / slug)
        mine = set()
        for fn in ('native.json', 'semgrep.json', 'gitleaks.json'):
            for o in json.loads((d / fn).read_text(encoding='utf-8')):
                mine.add ((o['file'], o['line']))
        res: dict[str, object] = {'repo': slug, 'mine': len(mine)}

        # 1. Semgrep default ruleset.
        with tempfile.TemporaryDirectory() as td:
            out = str(Path(td) / 's.json')
            code, _, err = run(
                [SEMGREP, '--config', PACK[lang], '--quiet', '--json',
                 '--output', out, repo], 600)
            sset: set[tuple[str, int]] = set()
            try:
                data = json.loads(Path(out).read_text(encoding='utf-8'))
                for r in data.get('results', []):
                    pth = r.get('path', '').replace('\\', '/')
                    sset.add((pth.split('bench-repos/')[-1].split('/', 1)[-1]
                              if 'bench-repos/' in pth else pth,
                              r.get('start', {}).get('line', 0)))
                Path(ext / 'semgrep-default.json').write_text(
                    json.dumps(data.get('results', []), indent=2), encoding='utf-8')
            except Exception as exc:  # noqa: BLE001
                err = (err + ' | ' + str(exc))[:200]
            res['semgrep_default'] = len(sset)
            res['semgrep_default_err'] = err.strip()[:150]
            res['semgrep_default_overlap'] = len(mine & sset)
            # rule breakdown for the report
            try:
                from collections import Counter
                res['semgrep_default_rules'] = Counter(
                    (r.get('check_id', '').split('.')[-1]) for r in
                    json.loads((ext / 'semgrep-default.json').read_text(encoding='utf-8'))
                ).most_common(6)
            except Exception:  # noqa: BLE001
                pass

        # 2. Bandit (Python) / njsscan (JS-TS).
        for tool, exe, langs, flag in [
            ('bandit', BANDIT, ('Python',), ['-r', '-f', 'json']),
            ('njsscan', NJSSCAN, ('JavaScript', 'TypeScript'), ['--json']),
        ]:
            if lang not in langs:
                continue
            with tempfile.TemporaryDirectory() as td:
                out = str(Path(td) / 'o.json')
                if tool == 'bandit':
                    code, so, err = run([exe] + flag + ['-o', out, repo], 300)
                else:
                    code, so, err = run([exe, repo, '--json', '-o', out], 300)
                tset: set[tuple[str, int]] = set()
                try:
                    raw = Path(out).read_text(encoding='utf-8')
                    Path(ext / (tool + '.json')).write_text(raw, encoding='utf-8')
                    data = json.loads(raw)
                    items = (data.get('results', []) if isinstance(data, dict)
                             else data.get('errors', []) if isinstance(data, dict) else data)
                    for r in (items or []):
                        fn = r.get('filename', '') or r.get('file', '')
                        fn = fn.replace('\\', '/')
                        ln = r.get('line_number', 0) or r.get('line', 0) or 0
                        tset.add((fn.split('bench-repos/')[-1].split('/', 1)[-1]
                                  if 'bench-repos/' in fn else fn, ln))
                except Exception as exc:  # noqa: BLE001
                    err = (err + ' | ' + str(exc))[:200]
                res[tool] = len(tset)
                res[tool + '_overlap'] = len(mine & tset)
                res[tool + '_err'] = err.strip()[:150]
        (d / 'EXT-COMPARE.json').write_text(json.dumps(res, indent=2), encoding='utf-8')
        summary.append({k: v for k, v in res.items() if not k.endswith('_rules')})
        print(slug + ': mine=' + str(len(mine)) + ' ' +
              ' '.join(str(k) + '=' + str(res.get(k, '-')) for k in
                       ('semgrep_default', 'bandit', 'njsscan')), flush=True)
    (BASE / 'EXT-SUMMARY.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')


if __name__ == '__main__':
    sys.exit(main())
