import json, re, csv, os, sys, glob
from collections import Counter, defaultdict
A = "alt"; CV = re.compile(r"(?i)cve[-_]((?:19|20)\d{2})[-_](\d{4,7})")
def cves(s): return {"CVE-%s-%s" % m for m in CV.findall(s)}
T = json.load(open("research/data/templates.json")); N = set(T)
R = json.load(open("research/data/rules_with_cve.json")); E = {c for r in R["et_suri"] if r["enabled"] for c in r["cves"]}
print(f"nuclei http/cves: {len(N)} CVEs | ET Open (enabled rules): {len(E)} CVEs\n")
def report(name, X, note=""):
    X = set(X); new = X - N; r = lambda S_: [c for c in S_ if int(c.split("-")[1]) >= 2024]
    print(f"{name:34s} CVEs={len(X):6d} | in nuclei={len(X & N):5d} | NOT in nuclei={len(new):6d} (of these, no ET rule: {len(new - E):6d}) | 2024+: total={len(r(X)):5d} not-in-nuclei={len(r(new)):5d} no-ET={len(r(new - E)):5d} {note}")
tree = lambda n: [l.strip() for l in open(f"{A}/{n}/tree.txt")]
af = [p for p in tree("afrog") if p.lower().endswith((".yaml", ".yml")) and "pocs/" in p]
report("afrog PoC templates", set().union(*[cves(p) for p in af]), f"| files={len(af)}")
print("   afrog top dirs:", Counter("/".join(p.split("/")[:3]) for p in af).most_common(6))
xr = [p for p in tree("xray") if p.lower().endswith((".yaml", ".yml")) and p.startswith("pocs/")]
report("xray PoC templates", set().union(*[cves(p) for p in xr]) if xr else set(), f"| files={len(xr)}")
vh = [p for p in tree("vulhub") if p.endswith("docker-compose.yml")]
report("vulhub environments (targets)", set().union(*[cves(p) for p in vh]), f"| envs={len(vh)}")
bc = [p for p in tree("bchecks") if p.endswith(".bcheck")]
report("Burp BChecks", set().union(*[cves(p) for p in bc]) if bc else set(), f"| files={len(bc)}")
pg = [p for p in tree("pocgh") if p.endswith(".json")]
report("PoC-in-GitHub index (free-form)", set().union(*[cves(os.path.basename(p)) for p in pg]), f"| files={len(pg)}")
print("   PoC-in-GitHub by year:", sorted(Counter(p.split("/")[0] for p in pg).items())[-6:])
M = json.load(open(f"{A}/msf/data")); mods = list(M.values())
print(f"\nmetasploit modules: {len(mods)} | by type:", dict(Counter(m.get('type') for m in mods).most_common(5)))
http = [m for m in mods if m.get("type") in ("exploit", "auxiliary") and re.search(r"/(http|webapp)/", m.get("fullname", ""))]
ex = [m for m in http if m["type"] == "exploit"]
report("metasploit HTTP exploit modules", set().union(*[cves(" ".join(m.get("references") or [])) for m in ex]), f"| modules={len(ex)}")
report("metasploit HTTP auxiliary modules", set().union(*[cves(" ".join(m.get("references") or [])) for m in http if m["type"] == "auxiliary"]), f"| modules={len(http) - len(ex)}")
print("   msf HTTP exploit modules by disclosure year:", sorted(Counter((m.get("disclosure_date") or "none")[:4] for m in ex).items())[-6:])
rows = list(csv.DictReader(open(f"{A}/edb/data", encoding="utf-8", errors="replace")))
web = [r for r in rows if r.get("type") == "webapps"]
print(f"\nexploit-db entries: {len(rows)} | webapps: {len(web)} | by type:", dict(Counter(r.get('type') for r in rows)))
report("exploit-db webapps (free-form)", set().union(*[cves(r.get("codes") or "") for r in web]), f"| with CVE code: {sum(bool(cves(r.get('codes') or '')) for r in web)}")
print("   exploit-db webapps published per year:", sorted(Counter((r.get("date_published") or "")[:4] for r in web).items())[-7:])
K = json.load(open(f"{A}/kev/data"))["vulnerabilities"]; kc = {v["cveID"] for v in K}
report("CISA KEV (priority list, not PoC)", kc, f"| entries={len(K)}")
knew = [v for v in K if v["cveID"] not in N and v["cveID"] not in E]
print("   KEV with neither nuclei http template nor ET rule:", len(knew), "| top vendors:", Counter(v["vendorProject"] for v in knew).most_common(8))
sg = Counter()
import yaml
for p in glob.glob("src/sigma/rules*/**/*.yml", recursive=True):
    try: d = yaml.safe_load(open(p))
    except Exception: continue
    if isinstance(d, dict): sg[(d.get("logsource") or {}).get("category")] += 1
print("\nsigma rules by logsource category (webserver/proxy/network):", {k: v for k, v in sg.items() if k in ("webserver", "proxy", "firewall", "dns", "network_connection")}, "| total", sum(sg.values()))
crs = "".join(open(p, errors="replace").read() for p in glob.glob(f"{A}/crs/repo/rules/*.conf"))
print("CRS: SecRule count:", len(re.findall(r"^SecRule ", crs, re.M)), "| rules mentioning a CVE:", len(set(CV.findall(crs))), "| files:", len(glob.glob(f"{A}/crs/repo/rules/REQUEST-9*.conf")))
