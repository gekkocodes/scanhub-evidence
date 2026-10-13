#!/usr/bin/env python3
"""ScanHub Bench — CVE replay corpus builder.

Builds bench/corpus.json: real CVEs in pinned vulnerable versions of popular
open-source packages, with ground truth derived from the upstream fix commit.

Ground-truth rule (fixed 2026-10-13): hunk line numbers from the fix PR diff
are relative to the PR base, NOT the vulnerable tag, so they must never be
used as coordinates. We collect the '-' (pre-fix) line TEXTS from the fix
diff and locate them by exact stripped-text search in the vulnerable-tag
checkout. Lines that don't exist there are dropped. Multi-line advisories
pin the EARLIEST fixed version so the vuln_tag predates the first backport.
ops/corpus_qa.py prints the located lines for human verification.

This script only BUILDS and VALIDATES the corpus (clones repos, checks the
vulnerable code is present). Scoring lives in ops/benchmark.py --suite replay.
"""
import argparse, json, os, re, subprocess, sys, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BENCH = os.path.join(ROOT, "bench")
SRC = os.path.join(BENCH, "src")

# Hand-picked seed: popular packages, code-level CWEs, advisories known to
# carry commit references. Each entry is verified against OSV + the repo.
SEED = [
    # Application-level CVEs only (corpus rule 2026-10-11): the vulnerable code
    # lives in an application, so a pattern rule CAN match the fix-site shape.
    # Library-internal CVEs (lodash internals etc.) belong to the SCA lane.
    {"id": "GHSA-hpmr-prr2-cqc4", "pkg": "github.com/go-gitea/gitea", "eco": "Go", "cwe": "CWE-94",  "lang": "go"},   # RCE
    {"id": "GHSA-w8xw-7crf-h23x", "pkg": "github.com/go-gitea/gitea", "eco": "Go", "cwe": "CWE-88",  "lang": "go"},   # argument injection
    {"id": "GHSA-j5r2-4c8j-xc3m", "pkg": "github.com/go-gitea/gitea", "eco": "Go", "cwe": "CWE-601", "lang": "go"},   # open redirect
    {"id": "GHSA-36h2-95gj-w488", "pkg": "github.com/go-gitea/gitea", "eco": "Go", "cwe": "CWE-601", "lang": "go"},   # open redirect
    {"id": "GHSA-r3gq-wxqf-q4gh", "pkg": "github.com/go-gitea/gitea", "eco": "Go", "cwe": "CWE-79",  "lang": "go"},   # XSS
    {"id": "GHSA-q47x-6mqq-4w92", "pkg": "github.com/go-gitea/gitea", "eco": "Go", "cwe": "CWE-20",  "lang": "go"},   # input validation
    {"id": "GHSA-xh32-cx6c-cp4v", "pkg": "github.com/gogs/gogs",      "eco": "Go", "cwe": "CWE-79",  "lang": "go"},   # stored XSS via PDF renderer
    # Round 2 (2026-10-11): breadth beyond Go. Framework fixes whose SHAPE is
    # pattern-matchable (widget HTML concat, URL validation), not engine internals.
    {"id": "GHSA-7rp2-fm2h-wchj", "pkg": "django",       "eco": "PyPI", "cwe": "CWE-79",  "lang": "python"},  # XSS in AdminURLFieldWidget
    {"id": "GHSA-vq3h-3q7v-9prw", "pkg": "django",       "eco": "PyPI", "cwe": "CWE-601", "lang": "python"},  # open redirect (redirect_to)
    {"id": "GHSA-9cwg-mhxf-hh59", "pkg": "django",       "eco": "PyPI", "cwe": "CWE-601", "lang": "python"},  # is_safe_url bypass
    {"id": "GHSA-rv95-896h-c2vc", "pkg": "express",      "eco": "npm",  "cwe": "CWE-601", "lang": "javascript"},  # malformed-URL open redirect
    {"id": "GHSA-7px7-7xjx-hxm8", "pkg": "marked",       "eco": "npm",  "cwe": "CWE-79",  "lang": "javascript"},  # data-URI XSS
    {"id": "GHSA-qw6h-vgh9-j6wx", "pkg": "express",      "eco": "npm",  "cwe": "CWE-79",  "lang": "javascript"},  # XSS via response.redirect
    # Round 3 (2026-10-13): CWE-89 was unrepresented; these Django fixes are
    # SQL-string construction sites a python rule CAN match. serve-static
    # adds a second JS app-shape fix (redirect template injection).
    {"id": "GHSA-p64x-8rxx-wf6q", "pkg": "django",       "eco": "PyPI", "cwe": "CWE-89",  "lang": "python"},  # Trunc/Extract SQLi
    {"id": "GHSA-xpfp-f569-q3p2", "pkg": "django",       "eco": "PyPI", "cwe": "CWE-89",  "lang": "python"},  # ordering SQLi
    {"id": "GHSA-cm22-4g7w-348p", "pkg": "serve-static", "eco": "npm",  "cwe": "CWE-79",  "lang": "javascript"},  # redirect XSS
]


def osv_query(pkg, eco):
    body = json.dumps({"package": {"name": pkg, "ecosystem": eco}}).encode()
    req = urllib.request.Request("https://api.osv.dev/v1/query", data=body,
                                 headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=30).read())


def git(*args, cwd=None):
    r = subprocess.run(["git"] + list(args), cwd=cwd, capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr).strip()


def resolve_repo(pkg, eco, adv):
    """Find the upstream repo URL from OSV references."""
    for ref in adv.get("references", []):
        m = re.search(r"github\.com/([\w.-]+/[\w.-]+)", ref.get("url", ""))
        if m and not any(x in m.group(1) for x in ("advisories/", "nvd.nist", "osv.dev")) and not m.group(1).startswith("advisories"):
            cand = m.group(1)
            # prefer the repo that matches the package name
            if eco == "Go" or cand.split("/")[1].lower() in pkg.lower() or pkg.lower() in cand.replace("/", "-").lower():
                return "https://github.com/" + cand
    for ref in adv.get("references", []):
        m = re.search(r"github\.com/([\w.-]+/[\w.-]+)", ref.get("url", ""))
        if m and not m.group(1).startswith("advisories"):
            return "https://github.com/" + m.group(1)
    return None


def version_tags(repo, fixed_ver):
    """Return (fix_tag, prev_tag) closest to the fixed version."""
    _, out = git("tag", "--list", cwd=repo)
    tags = [t for t in out.splitlines() if t]
    def norm(t): return re.sub(r"^[vV]", "", t)
    def key(v):
        try: return tuple(int(x) for x in re.findall(r"\d+", v)[:3])
        except Exception: return (0,)
    fix = None
    for t in tags:
        if norm(t) == fixed_ver:
            fix = t; break
    if fix is None:  # loose match
        for t in sorted(tags, key=lambda t: key(norm(t))):
            if norm(t).startswith(fixed_ver):
                fix = t; break
    if fix is None:
        return None, None
    fixk = key(norm(fix))
    prevs = [t for t in tags if key(norm(t)) < fixk]
    prev = max(prevs, key=lambda t: key(norm(t))) if prevs else None
    return fix, prev


def pr_fix_commits(gid, repo_url):
    """GitHub API: advisory references -> merged PR merge-commit SHAs."""
    try:
        req = urllib.request.Request(f"https://api.github.com/advisories/{gid}",
            headers={"Accept": "application/vnd.github+json", "User-Agent": "scanhub-bench"})
        adv = json.loads(urllib.request.urlopen(req, timeout=30).read())
    except Exception:
        return []
    shas = []
    for ref in adv.get("references", []):
        m = re.match(r"(https://github\.com/([\w.-]+)/([\w.-]+))/pull/(\d+)$", ref)
        if not m or m.group(1) != repo_url.rstrip("/"):
            continue
        api = f"https://api.github.com/repos/{m.group(2)}/{m.group(3)}/pulls/{m.group(4)}"
        try:
            req = urllib.request.Request(api,
                headers={"Accept": "application/vnd.github+json", "User-Agent": "scanhub-bench"})
            pr = json.loads(urllib.request.urlopen(req, timeout=30).read())
            if pr.get("merge_commit_sha"):
                shas.append(pr["merge_commit_sha"])
        except Exception:
            pass
    return shas


def noise_path(p):
    if p.split("/")[0] in ("test", "tests", "docs", "doc", "examples"):
        return True
    return any(x in p for x in ("/vendor/", "_test.go", "/test/", ".spec.", ".test.",
                                "/tests/", "test_", ".min.", "changelog", "__init__.py",
                                "tests/", "docs/", "/doc/"))


def diff_deletions(diff_text):
    """{file: [removed line texts]} from a --unified=0 diff. The '-' side is
    the pre-fix (vulnerable) code. Hunk coordinates are relative to the PR
    base, NOT the vulnerable tag, so we locate these lines by text search."""
    files = {}
    cur = None
    for line in diff_text.splitlines():
        m = re.match(r"\+\+\+ b/(.+)", line)
        if m:
            cur = None if noise_path(m.group(1)) else m.group(1)
            if cur:
                files.setdefault(cur, [])
            continue
        if cur and line.startswith("-") and not line.startswith("---"):
            files[cur].append(line[1:])
    return files


def locate_truth(repo, vuln_tag, dels):
    """Check out vuln_tag and find the removed lines by exact stripped-text
    search. Returns {file: [[lo,hi],...]} in vulnerable-tree coordinates.
    Lines absent from the vulnerable tree (pure additions, refactors) are
    dropped - truth must exist where the scorer scans."""
    rc, _ = git("checkout", "-q", vuln_tag, cwd=repo)
    if rc != 0:
        return {}
    truth = {}
    for f, lines in dels.items():
        fp = os.path.join(repo, f)
        if not os.path.isfile(fp):
            continue
        try:
            tree = [l.strip() for l in open(fp, encoding="utf-8", errors="replace")]
        except OSError:
            continue
        hits = set()
        for dl in lines:
            s = dl.strip()
            if len(s) < 12 or sum(c.isalnum() for c in s) < 8:
                continue
            n = tree.count(s)
            if n == 0 or n > 20:
                continue  # absent (post-fix text) or too generic to be evidence
            for i, t in enumerate(tree, 1):
                if t == s:
                    hits.add(i)
        if not hits:
            continue
        hs = sorted(hits)
        rngs, start, prev = [], hs[0], hs[0]
        for x in hs[1:]:
            if x == prev + 1:
                prev = x
            else:
                rngs.append([start, prev])
                start = prev = x
        rngs.append([start, prev])
        truth[f] = rngs
    return truth


def build_entry(seed):
    q = osv_query(seed["pkg"], seed["eco"])
    adv = next((v for v in q.get("vulns", []) if v["id"] == seed["id"]), None)
    if adv is None:
        return {"seed": seed, "error": "advisory not found in OSV"}
    fixeds = []
    for aff in adv.get("affected", []):
        if aff["package"]["name"] != seed["pkg"]:
            continue
        for r in aff.get("ranges", []):
            if r.get("type") in ("ECOSYSTEM", "SEMVER", "GIT"):
                for e in r.get("events", []):
                    if "fixed" in e:
                        fixeds.append(e["fixed"])
    # Earliest fixed version: multi-line advisories (e.g. express 4.x + 5.x)
    # must pin the vuln_tag below the fix that applied FIRST, or the
    # "vulnerable" tag may already contain the backported fix.
    def vkey(v):
        nums = tuple(int(x) for x in re.findall(r"\d+", v)[:3])
        return (nums, 0 if "-" in v else 1, v)
    fixed = min(fixeds, key=vkey) if fixeds else None
    if not fixed:
        return {"seed": seed, "error": "no fixed version in OSV"}
    repo_url = resolve_repo(seed["pkg"], seed["eco"], adv)
    if not repo_url:
        return {"seed": seed, "error": "no repo reference"}
    name = seed["id"]
    path = os.path.join(SRC, name)
    if not os.path.isdir(path):
        os.makedirs(SRC, exist_ok=True)
        rc, out = git("clone", "--quiet", "-c", "core.longpaths=true", repo_url, path)
        if rc != 0:
            return {"seed": seed, "error": "clone failed: " + out[-200:]}
    git("fetch", "--tags", "--quiet", cwd=path)
    fix_tag, prev_tag = version_tags(path, fixed)
    # Ground truth: collect the '-' (pre-fix) lines from the fix diff, then
    # locate them by text search in the vulnerable checkout. Hunk coordinates
    # lie (PR base != vulnerable tag); text search does not.
    dels = {}
    truth_mode = None
    for sha in pr_fix_commits(seed["id"], repo_url):
        rc, diff = git("diff", "--unified=0", sha + "^", sha, "--", "*.js", "*.ts", "*.py", "*.go", cwd=path)
        if rc == 0:
            for f, ls in diff_deletions(diff).items():
                dels.setdefault(f, []).extend(ls)
    if dels:
        truth_mode = "pr"
    if not dels and fix_tag and prev_tag:
        _, diff = git("diff", "--unified=0", f"{prev_tag}..{fix_tag}", "--", "*.js", "*.ts", "*.py", "*.go", cwd=path)
        dels = diff_deletions(diff)
        truth_mode = "tagdiff"
    if not dels:
        return {**seed, "error": "no deletions in fix diff"}
    if not prev_tag:
        return {**seed, "error": f"no vulnerable tag below fixed={fixed}"}
    truth = locate_truth(path, prev_tag, dels)
    if not truth:
        return {**seed, "error": "no deleted lines located in the vulnerable tree"}
    if len(truth) > 50:
        # A release diff touching >50 source files is noise, not truth: any
        # same-CWE finding anywhere would score as a TP. Needs a PR ref instead.
        return {**seed, "error": f"tagdiff too broad ({len(truth)} truth files)"}
    return {
        "id": seed["id"], "pkg": seed["pkg"], "eco": seed["eco"], "lang": seed["lang"],
        "cwe": seed["cwe"], "fixed": fixed, "vuln_tag": prev_tag, "fix_tag": fix_tag,
        "repo": repo_url, "src": os.path.relpath(path, ROOT).replace("\\", "/"),
        "truth_mode": truth_mode,
        "truth": [{"file": f, "lines": rng} for f, rng in truth.items()],
        "aliases": adv.get("aliases", []),
        "summary": (adv.get("summary") or adv.get("details") or "")[:160],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="build a single advisory id")
    args = ap.parse_args()
    os.makedirs(SRC, exist_ok=True)
    out, fails = [], []
    for seed in SEED:
        if args.only and seed["id"] != args.only:
            continue
        print(f"[corpus] {seed['id']} {seed['pkg']} …", flush=True)
        try:
            e = build_entry(seed)
        except Exception as ex:
            e = {"seed": seed, "error": str(ex)}
        if "error" in e:
            print(f"   SKIP: {e['error']}")
            fails.append(e)
        else:
            print(f"   OK: {e['vuln_tag']} -> {e['fix_tag']}, {len(e['truth'])} truth files")
            out.append(e)
    p = os.path.join(BENCH, "corpus.json")
    json.dump(out, open(p, "w", encoding="utf-8"), indent=1)
    print(f"\n[corpus] wrote {p}: {len(out)} entries, {len(fails)} skipped")
    for f in fails:
        fid = f.get("id") or f.get("seed", {}).get("id", "?")
        print("  fail:", fid, "-", f["error"])


if __name__ == "__main__":
    main()
