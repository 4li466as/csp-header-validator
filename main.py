import argparse, json, sys, logging, re, pathlib, glob, requests
from typing import List, Dict, Tuple

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def fetch_csp(url: str, timeout: int, ua: str, proxy: str) -> Dict[str, str]:
    hdrs = {'User-Agent': ua}
    proxies = {'http': proxy, 'https': proxy} if proxy else None
    try:
        r = requests.get(url, timeout=timeout, headers=hdrs, proxies=proxies)
        return {k.lower(): v for k, v in r.headers.items() if k.lower().startswith('content-security-policy')}
    except Exception as e:
        logging.error(f'Failed to fetch {url}: {e}')
        return {}

def parse_csp(value: str) -> Dict[str, List[str]]:
    dirs: Dict[str, List[str]] = {}
    for part in filter(None, re.split(r";\s*", value)):
        toks = part.strip().split()
        if toks:
            dirs[toks[0].lower()] = toks[1:]
    return dirs

def validate_csp(dirs: Dict[str, List[str]]) -> List[str]:
    issues = []
    for d, srcs in dirs.items():
        if '*' in srcs:
            issues.append(f"{d} contains wildcard '*'")
        for s in srcs:
            if re.match(r"^'unsafe-.*'", s):
                issues.append(f"{d} uses unsafe source {s}")
    return issues

def score_csp(dirs: Dict[str, List[str]], whitelist: List[str]) -> Tuple[int, List[str]]:
    score, recs = 100, []
    if 'default-src' not in dirs:
        score -= 20; recs.append('Add default-src "self"')
    elif "'self'" not in dirs['default-src']:
        score -= 10; recs.append('default-src should include "self"')
    for d, srcs in dirs.items():
        if '*' in srcs:
            score -= 15; recs.append(f'Replace wildcard in {d}')
        for s in srcs:
            if s.startswith('http') and not any(w in s for w in whitelist):
                score -= 5
    return max(score, 0), recs

def load_targets(target: str) -> List[str]:
    p = pathlib.Path(target)
    if p.is_file():
        return [l.strip() for l in p.read_text().splitlines() if l.strip()]
    if any(ch in target for ch in '*?['):
        return [str(p) for p in glob.glob(target)]
    return [target]

def main(argv: List[str] = None):
    if argv is None:
        argv = sys.argv[1:]
    ap = argparse.ArgumentParser(description='Validate CSP headers')
    ap.add_argument('target')
    ap.add_argument('-o', '--output')
    ap.add_argument('-t', '--threshold', type=int, default=80)
    ap.add_argument('--allow', action='append', default=[])
    ap.add_argument('--timeout', type=int, default=5)
    ap.add_argument('--user-agent', default='csp-validator/1.0')
    ap.add_argument('--proxy')
    ap.add_argument('-q', '--quiet', action='store_true')
    args = ap.parse_args(argv)

    results = []
    for url in load_targets(args.target):
        hdrs = fetch_csp(url, args.timeout, args.user_agent, args.proxy)
        present = bool(hdrs)
        issues, score, recs = [], 0, []
        if present:
            csp_val = hdrs.get('content-security-policy') or hdrs.get('content-security-policy-report-only')
            dirs = parse_csp(csp_val)
            issues = validate_csp(dirs)
            score, recs = score_csp(dirs, args.allow)
        results.append({'url': url, 'present': present, 'score': score, 'issues': issues, 'recommendations': recs})
        if not args.quiet:
            logging.info(f"{url} -> score {score}, present={present}")

    if args.output:
        ext = pathlib.Path(args.output).suffix.lower()
        if ext == '.csv':
            import csv
            with open(args.output, 'w', newline='') as f:
                w = csv.DictWriter(f, fieldnames=['url','present','score','issues','recommendations'])
                w.writeheader(); w.writerows(results)
        else:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
    else:
        json.dump(results, sys.stdout, indent=2)

    exit_code = 0 if all(r['score'] >= args.threshold for r in results) else 1
    sys.exit(exit_code)

if __name__ == '__main__':
    main()