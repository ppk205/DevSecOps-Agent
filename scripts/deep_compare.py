"""Full deep-scan: my app (--profile full, deterministic) + 3 external apps
(semgrep --config auto, bandit, njsscan) on 5 repos (1 per language).

Output: artifacts/deep-compare/<slug>/ {manifest.json, mine/* (full exports),
external/semgrep-auto.json, external/bandit.json, external/njsscan.json,
DEEP-COMPARE.md}.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPOS = {'problem-spring-web': 'Java', 'thelounge': 'JavaScript',
         'vue-mdc': 'TypeScript', 'falcon': 'Python', 'pikachu': 'PHP'}
DEVSEC = '.venv/Scripts/devsec.exe'
SEMGREP = '.venv/Scripts/semgrep.exe'
BANDIT = '.venv/Scripts/bandit.exe'
NJSSCAN = '.venv/Scripts/njsscan.exe'
BASE = Path('artifacts/deep-compare')


def run(cmd: list[str], timeout: int) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr)[-500:]
    except subprocess.TimeoutExpired:
        return 124, 'TIMEOUT'


def main() -> None:
    BASE.mkdir(parents=True, exist_ok=True)
    for slug, lang in REPOS.items():
        d = BASE / slug
        (d / 'mine').mkdir(parents=True, exist_ok=True)
        (d / 'external').mkdir(parents=True, exist_ok=True)
        bench_manifest = json.loads(
            (Path('artifacts/bench-compare') / slug / 'manifest.json').read_text(encoding='utf-8'))
        man = {'repo': slug, 'lang': lang, 'url': bench_manifest['url'],
               'commit': bench_manifest['commit']}
        # 1. My app, full profile, deterministic (no AI: upstream flaky; recorded).
        code, tail = run(
            [DEVSEC, 'scan-run', '--checkout', 'D:/dev/bench-repos/' + slug,
             '--out', 'artifacts/deep-compare/%s/mine' % slug,
             '--profile', 'full', '--allow-dirty',
             '--db-path', 'D:/dev/deep-compare.db'], 1800)
        man['mine_exit'] = code
        man['mine_tail'] = tail[-300:]
        # 2. Semgrep full registry (--config auto).
        with tempfile.TemporaryDirectory() as td:
            out = str(Path(td) / 's.json')
            code, tail = run(
                [SEMGREP, '--config', 'auto', '--quiet', '--json',
                 '--output', out, 'D:/dev/bench-repos/' + slug], 1200)
            try:
                (d / 'external' / 'semgrep-auto.json').write_text(
                    Path(out).read_text(encoding='utf-8'), encoding='utf-8')
                man['semgrep_auto_n'] = len(json.loads(
                    (d / 'external' / 'semgrep-auto.json').read_text(encoding='utf-8')
                ).get('results', []))
            except Exception as exc:  # noqa: BLE001
                man['semgrep_auto_err'] = str(exc)[:150] + ' | ' + tail[-150:]
        # 3. Bandit / njsscan (defaults already full).
        if lang == 'Python':
            with tempfile.TemporaryDirectory() as td:
                out = str(Path(td) / 'b.json')
                code, tail = run([BANDIT, '-r', '-f', 'json', '-o', out,
                                  'D:/dev/bench-repos/' + slug], 600)
                try:
                    (d / 'external' / 'bandit.json').write_text(
                        Path(out).read_text(encoding='utf-8'), encoding='utf-8')
                except Exception as exc:  # noqa: BLE001
                    man['bandit_err'] = str(exc)[:150]
        if lang in ('JavaScript', 'TypeScript'):
            with tempfile.TemporaryDirectory() as td:
                out = str(Path(td) / 'n.json')
                code, tail = run([NJSSCAN, 'D:/dev/bench-repos/' + slug,
                                  '--json', '-o', out], 600)
                try:
                    (d / 'external' / 'njsscan.json').write_text(
                        Path(out).read_text(encoding='utf-8'), encoding='utf-8')
                except Exception as exc:  # noqa: BLE001
                    man['njsscan_err'] = str(exc)[:150]
        (d / 'manifest.json').write_text(json.dumps(man, indent=2), encoding='utf-8')
        print(slug + ': ' + json.dumps(man), flush=True)


if __name__ == '__main__':
    sys.exit(main())
