#!/usr/bin/env python3
"""ScanHub benchmark harness — reproducible, client-verifiable detection evidence.

Scans a public benchmark application end-to-end through the public REST API
(no DB access, no privileged paths) and emits an evidence pack:

  evidence/<app>-<date>.json   raw findings + environment fingerprint
  evidence/<app>-<date>.md     human-readable report (client-facing)
  evidence/<app>-latest.json   symlink-style copy for regression diffing

Anyone can re-run this against their own ScanHub instance and reproduce the
numbers. That is the proof story: not "trust our blog post", but "run this
script yourself".

Usage:
  python ops/benchmark.py --url http://localhost:8080 --token <api-token>
  python ops/benchmark.py --url ... --email a@b.c --password pw   # mints temp token
  python ops/benchmark.py --app dvja --url ... --token ...

Apps: juice-shop (default), dvja (Damn Vulnerable Java App).
"""
import argparse, datetime, hashlib, io, json, os, platform, re, shutil, ssl, subprocess, sys, urllib.error, urllib.parse, urllib.request, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
EVID = os.path.join(ROOT, "evidence")

APPS = {
    "juice-shop": "https://codeload.github.com/juice-shop/juice-shop/tar.gz/refs/heads/master",
    "dvja": "https://codeload.github.com/ajaysenr/dvja/tar.gz/refs/heads/master",
    "pygoat": "https://codeload.github.com/adeyosemanputra/pygoat/tar.gz/refs/heads/master",
}

def log(msg): print(f"[bench] {msg}", flush=True)

def http(url, data=None, headers=None, method=None, timeout=120):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    ctx = ssl.create_default_context()
    return urllib.request.urlopen(req, timeout=timeout, context=ctx)

def get_app_zip(app, cache_dir):
    os.makedirs(cache_dir, exist_ok=True)
    zp = os.path.join(cache_dir, app + ".zip")
    if not os.path.exists(zp):
        log(f"downloading {app} source…")
        raw = http(APPS[app], timeout=600).read()
        # source archives are tar.gz; convert to zip (ScanHub takes zips)
        import tarfile
        buf = io.BytesIO(raw)
        with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED) as zf:
            with tarfile.open(fileobj=buf, mode="r:gz") as tf:
                for m in tf.getmembers():
                    if m.isfile() and "/node_modules/" not in m.name:
                        zf.writestr(m.name, tf.extractfile(m).read())
    h = hashlib.sha256(open(zp, "rb").read()).hexdigest()
    log(f"{app} zip ready: {os.path.getsize(zp)} bytes sha256={h[:16]}…")
    return zp, h

def api(url, token, path, **kw):
    return http(url + path, headers={"Authorization": "Bearer " + token}, **kw)

def mint_token(url, email, password):
    """Web login (CSRF) -> create API token -> return it."""
    cj = __import__("http.cookiejar", fromlist=["CookieJar"]).CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    def tok(html): return re.search(r'name="csrf" value="([^"]+)"', html).group(1)
    html = op.open(url + "/login").read().decode()
    op.open(urllib.request.Request(url + "/login", data=urllib.parse.urlencode(
        {"csrf": tok(html), "email": email, "password": password}).encode()))
    html = op.open(url + "/settings/api").read().decode()
    r = op.open(urllib.request.Request(url + "/api/v1/tokens",
        data=urllib.parse.urlencode({"csrf": tok(html), "name": "benchmark"}).encode()))
    return json.loads(r.read())["token"]

def env_fingerprint(url):
    fp = {"timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
          "host": platform.node(), "python": sys.version.split()[0]}
    try:
        fp["scanhub_health"] = json.loads(http(url + "/healthz", timeout=10).read()).get("version", "unknown")
    except Exception: pass
    for name, img in (("opengrep", "ipvsix/opengrep:latest"), ("gitleaks", "ghcr.io/gitleaks/gitleaks:latest")):
        try:
            out = subprocess.run(["docker", "run", "--rm", img, "--version"],
                                 capture_output=True, text=True, timeout=120)
            fp[name] = (out.stdout + out.stderr).strip().splitlines()[0][:80]
        except Exception:
            fp[name] = "unavailable"
    rules_dir = os.path.join(ROOT, "rules")
    fp["rule_files"] = sorted(f for f in os.listdir(rules_dir) if f.endswith(".yaml"))
    fp["rule_count"] = sum(open(os.path.join(rules_dir, f), encoding="utf-8").read().count("- id: ")
                           for f in fp["rule_files"])
    try:
        fp["scanhub_commit"] = subprocess.run(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"],
                                              capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception: pass
    return fp

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8080")
    ap.add_argument("--token"); ap.add_argument("--email"); ap.add_argument("--password")
    ap.add_argument("--app", default="juice-shop", choices=sorted(APPS))
    ap.add_argument("--cache", default=os.path.join(ROOT, "_data"))
    a = ap.parse_args()
    token = a.token or mint_token(a.url, a.email, a.password)

    zp, sha = get_app_zip(a.app, a.cache)
    fp = env_fingerprint(a.url)

    log("creating project…")
    proj = json.loads(http(a.url + "/api/v1/projects",
        data=json.dumps({"name": f"Bench: {a.app}"}).encode(),
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"}).read())["id"]

    log("uploading source…")
    boundary = "bench" + "0" * 8
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"zip\"; filename=\"{a.app}.zip\"\r\n"
            f"Content-Type: application/zip\r\n\r\n").encode() + open(zp, "rb").read() + f"\r\n--{boundary}--\r\n".encode()
    scan = json.loads(http(a.url + f"/api/v1/projects/{proj}/scans", data=body,
        headers={"Authorization": "Bearer " + token,
                 "Content-Type": "multipart/form-data; boundary=" + boundary}).read())
    sid = scan["scan_id"]
    log(f"scan {sid} queued; polling…")

    while True:
        st = json.loads(api(a.url, token, f"/api/v1/scans/{sid}").read())
        if st.get("status") in ("done", "failed"): break
        import time; time.sleep(15)
    if st.get("status") != "done":
        sys.exit(f"scan failed: {st.get('error')}")

    data = json.loads(api(a.url, token, f"/api/v1/scans/{sid}/findings").read())
    data["scan_id"] = sid
    data["app"] = a.app
    data["app_zip_sha256"] = sha
    data["environment"] = fp
    data["severity_counts"] = {}
    for f in data["findings"]:
        data["severity_counts"][f["severity"]] = data["severity_counts"].get(f["severity"], 0) + 1

    os.makedirs(EVID, exist_ok=True)
    date = datetime.date.today().isoformat()
    jp = os.path.join(EVID, f"{a.app}-{date}.json")
    json.dump(data, open(jp, "w"), indent=1)
    json.dump(data, open(os.path.join(EVID, f"{a.app}-latest.json"), "w"), indent=1)
    log(f"evidence JSON: {jp} ({len(data['findings'])} findings)")

    # markdown report
    md = [f"# ScanHub detection evidence — {a.app}", "",
          f"- **Date:** {date}", f"- **ScanHub build:** `{fp.get('scanhub_commit','?')}` @ `{a.url}`",
          f"- **Rules:** {fp['rule_count']} original ScanHub rules ({', '.join(fp['rule_files'])})",
          f"- **Engines:** opengrep `{fp.get('opengrep','?')}` · gitleaks `{fp.get('gitleaks','?')}`",
          f"- **Benchmark source:** {APPS[a.app]} (sha256 `{sha[:16]}…`)",
          f"- **Scan id:** `{sid}`", "",
          f"**Result: {len(data['findings'])} findings** — " +
          ", ".join(f"{v} {k}" for k, v in sorted(data["severity_counts"].items())), "",
          "## Findings by rule", "", "| Rule | Engine | Count |", "|---|---|---|"]
    byrule = {}
    for f in data["findings"]:
        k = (f["rule"], f["engine"]); byrule[k] = byrule.get(k, 0) + 1
    for (rule, eng), n in sorted(byrule.items(), key=lambda x: -x[1]):
        md.append(f"| `{rule}` | {eng} | {n} |")
    md += ["", "## Reproduce", "", "```bash",
           f"python ops/benchmark.py --url <your-instance> --token <api-token> --app {a.app}", "```", "",
           "The harness uses only the public REST API. Findings land in `evidence/` for diffing.", ""]
    mp = os.path.join(EVID, f"{a.app}-{date}.md")
    open(mp, "w", encoding="utf-8").write("\n".join(md))
    log(f"evidence MD:   {mp}")

    # regression check vs previous run, then rotate latest -> prev
    prev_p = os.path.join(EVID, f"{a.app}-prev.json")
    latest_p = os.path.join(EVID, f"{a.app}-latest.json")
    if os.path.exists(prev_p):
        prev = json.load(open(prev_p))
        if len(data["findings"]) < len(prev["findings"]):
            sys.exit(f"REGRESSION: {len(data['findings'])} < previous {len(prev['findings'])}")
        log(f"no regression vs previous run ({len(prev['findings'])})")
    if os.path.exists(latest_p):
        shutil.copy(latest_p, prev_p)
    shutil.copy(jp, latest_p)
    log("done")

if __name__ == "__main__":
    main()
