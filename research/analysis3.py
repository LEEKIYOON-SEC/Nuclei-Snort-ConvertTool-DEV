import json, re, sys, os, statistics as st
from collections import Counter, defaultdict
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); import pilot
R = json.load(open("research/data/results3.json")); PF = json.load(open("research/data/path_freq.json"))
ET = json.load(open("research/data/et_rules_for_nuclei_cves.json")); et_by_cve = defaultdict(list)
for x in ET:
    for c in x["cves"]: et_by_cve[c].append(x)
def pct(a, b): return "%d/%d (%.0f%%)" % (a, b, 100 * a / b if b else 0)
def tab(title, c, total=None):
    total = total or sum(c.values()); print("\n" + title)
    for k, v in sorted(c.items(), key=lambda x: -x[1]): print(f"  {v:5d}  {100*v/total:5.1f}%  {k}")
N = len(R); have = [r for r in R if r["reqA"] + r["reqB"] > 0]
print("== A. eliciting requests offline ==")
print("templates:", N, "| any request captured:", pct(len(have), N), "| from original template:", pct(sum(r["reqA"] > 0 for r in R), N), "| from flow-stripped copy:", pct(sum(r["reqB"] > 0 for r in R), N))
conv = [r for r in R if r["pilot"] == "converted"]
tab("pilot outcome", Counter(r["pilot"] for r in R))
tab("picked (attack) request seen on the wire, converted templates", Counter("+".join(r["picked_seen"]) or "never" for r in conv))
multi = [r for r in conv if (r["n_def"] or 0) > 1]
print("  multi-request templates:", len(multi), "| picked request seen from ORIGINAL template:", pct(sum("A" in r["picked_seen"] for r in multi), len(multi)), "| after flow-strip:", pct(sum("B" in r["picked_seen"] for r in multi), len(multi)))
INFO = ("ET INFO", "ET POLICY", "ET HUNTING", "ET USER_AGENTS", "ET DNS", "ET TA_ABUSED", "ET FILE_SHARING", "ET GAMES", "ET CHAT", "ET INAPPROPRIATE", "ET REMOTE_ACCESS", "ET ADWARE", "ET JA3", "ET TOR")
def et_class(r):
    if r["et_dedicated"]: return "1 dedicated CVE rule fired"
    att = [m for s, m in r["et_other"] if not m.startswith(INFO)]
    if att: return "2 no dedicated rule, generic attack-class rule fired"
    if r["et_other"]: return "3 informational alert only"
    return "4 no alert"
print("\n== B. does the full ET Open ruleset (Suricata) alert on the nuclei traffic? ==")
for label, sub in (("all templates with traffic", have), ("CVE has an ET rule", [r for r in have if r["has_et_rule"]]), ("CVE has NO ET rule", [r for r in have if not r["has_et_rule"]])):
    tab(f"{label} (n={len(sub)})", Counter(et_class(r) for r in sub))
tab("top generic ET signatures on traffic of CVEs without a dedicated ET rule (templates)", Counter(m for r in have if not r["has_et_rule"] for m in {m for s, m in r["et_other"] if not m.startswith(INFO)}), total=sum(not r["has_et_rule"] for r in have))
miss = [r for r in have if r["has_et_rule"] and not r["et_dedicated"]]
kinds = Counter()
for r in miss:
    ks = {x["kind"] for x in et_by_cve[r["id"]]}; kinds["only response-side/non-http rules" if ks <= {"response-side", "raw-payload"} else "request-side rule exists but did not match nuclei's request"] += 1
tab("CVE has ET rule but it did not fire on nuclei traffic (n=%d)" % len(miss), kinds)
print("\n== C. pilot rules replayed in three engines ==")
def ndet(r, both=False): return sum((set(r["det"][e]) >= {"A", "B"}) if both else bool(r["det"][e]) for e in ("suri", "s2", "s3"))
tab("engines that alerted (own rule, own traffic), converted templates", Counter("%d/3" % ndet(r) for r in conv))
print("  per engine:", {e: sum(bool(r["det"][e]) for r in conv) for e in ("suri", "s2", "s3")})
z = [r for r in conv if ndet(r) == 0]
tab("zero-detection breakdown", Counter("picked request never on the wire (unverifiable)" if not r["picked_seen"] else "picked request was sent but rule did not match" for r in z))
part = [r for r in conv if 0 < ndet(r) < 3]
tab("partial detection: which engines missed", Counter("missed by " + ",".join(e for e in ("suri", "s2", "s3") if not r["det"][e]) for r in part))
two = [r for r in conv if set(r["picked_seen"]) >= {"A", "B"}]
print("\n  attack request sent in both runs (different random values):", len(two), "| alerted in both runs in all 3 engines:", pct(sum(ndet(r, True) == 3 for r in two), len(two)), "| alerted only in one run in some engine:", sum(ndet(r) == 3 and ndet(r, True) < 3 for r in two))
cf = defaultdict(set)
for r in R:
    for e in ("suri", "s2", "s3"):
        for other in r["cross"][e]: cf[other].add(r["id"])
print("\n  pilot rules that alerted on ANOTHER template's traffic:", pct(len(cf), len(conv)), "| firing on >=5 other templates:", sum(len(v) >= 5 for v in cf.values()))
byid = {r["id"]: r for r in R}
for k, v in sorted(cf.items(), key=lambda x: -len(x[1]))[:12]: print(f"    {len(v):4d} others  {k}  U={byid[k]['picked']['U'][:2]} B={[b[:40] for b in byid[k]['picked']['B'][:2]]}")
print("\n== D. same CVE: professional ET rule vs pilot rule ==")
both = [r for r in have if r["et_dedicated"]]
tab("CVE where the dedicated ET rule fired on nuclei traffic (n=%d): pilot outcome" % len(both), Counter(
    ("pilot rule fired on the SAME request" if r["et_ded_same_tx_as_pilot"] else "pilot rule fired on a DIFFERENT request" if ndet(r) else "pilot rule made but did not fire") if r["pilot"] == "converted" else "pilot skipped: " + r["pilot"] for r in both))
# ---- quality proxies
PAY = re.compile(r"(?i)\.\./|etc/passwd|win\.ini|<script|alert\(|onerror|onload|onfocus|javascript:|<svg|<img|union[\s+%]|select[\s+%(]|sleep\(|waitfor|benchmark\(|pg_sleep|extractvalue|updatexml|' ?(or|and) |\$\{|<\?php|<%|whoami|;id|\|id|`id`|/bin/|cmd\.exe|wget |curl |nslookup|ping |jndi:|runtime|exec\(|system\(|eval\(|passthru|file://|gopher://|dict://|php://|data:|expect://|%00|<!entity|<!doctype|\{\{.*\}\}|__proto__|constructor|\bcat |\becho |md5\(|print\(|phpinfo")
def norm(uri):
    p = pilot.BASE.sub("", uri).split("?")[0].split("#")[0]; return (pilot.VAR.sub("{}", p).rstrip("/") or "/").lower()
def evidence(r):
    p = r["picked"]; text = " ".join(p["U"] + p["B"]); shared = PF.get(norm(p["uri"]), 1)
    has_q = any(("?" in u or "=" in u) for u in p["U"]); r["path_shared"] = shared
    if PAY.search(text): return "1 payload string in request (attack syntax visible; PoC-specific)"
    if p["B"] or has_q: return "2 endpoint + parameter/body structure, no payload string" + (" [shared endpoint]" if shared >= 5 else "")
    return "3 path only, endpoint unique to this template" if shared <= 1 else "4 path only, endpoint shared by %s templates" % ("2-4" if shared < 5 else ">=5")
for r in conv: r["ev"] = evidence(r)
print("\n== E. what the pilot rules actually match on (heuristic classes) ==")
tab("converted templates (n=%d)" % len(conv), Counter(r["ev"] for r in conv))
tab("...of which alerted in all 3 engines", Counter(r["ev"] for r in conv if ndet(r) == 3))
print("\n  cross-firing rules by class:", dict(Counter(byid[k]["ev"][:1] for k in cf)))
ORDER = [("sqli", ("sqli", "time-based-sqli", "sql-injection")), ("xss", ("xss",)), ("lfi/traversal", ("lfi", "traversal", "path-traversal", "file-read", "lfr")), ("xxe", ("xxe",)), ("ssrf", ("ssrf",)),
         ("file-upload", ("file-upload", "fileupload")), ("rce/injection", ("rce", "cmdi", "ssti", "deserialization", "injection", "code-injection", "command-injection")), ("redirect", ("redirect", "open-redirect")),
         ("auth-bypass", ("auth-bypass", "account-takeover", "default-login", "jwt", "unauth-access", "privesc")), ("info/exposure", ("exposure", "disclosure", "info-leak", "idor", "misconfig", "enum"))]
def vclass(r):
    for name, tags in ORDER:
        if set(tags) & set(r["tags"]): return name
    return "other"
print("\n  by vulnerability class: n | converted | 3-engine detect | payload-visible | path-only | has ET rule")
for name in [o[0] for o in ORDER] + ["other"]:
    sub = [r for r in R if vclass(r) == name]; c = [r for r in sub if r["pilot"] == "converted"]
    if not sub: continue
    print(f"    {name:15s} {len(sub):4d} | {100*len(c)/len(sub):3.0f}% | {100*sum(ndet(r)==3 for r in c)/max(1,len(c)):3.0f}% | {100*sum(r['ev'][0]=='1' for r in c)/max(1,len(c)):3.0f}% | {100*sum(r['ev'][0] in '34' for r in c)/max(1,len(c)):3.0f}% | {100*sum(r['has_et_rule'] for r in sub)/len(sub):3.0f}%")
print("\n  by year: n | converted | 3-engine detect")
for y in (2024, 2025, 2026):
    sub = [r for r in R if r["year"] == y]; c = [r for r in sub if r["pilot"] == "converted"]
    print(f"    {y} {len(sub):4d} | {pct(len(c), len(sub))} | {pct(sum(ndet(r)==3 for r in c), len(c))}")
print("\n  ET rule kinds for the same CVEs vs pilot class (CVE count):")
m = Counter()
for r in conv:
    if r["has_et_rule"] and et_by_cve[r["id"]]:
        ks = Counter(x["kind"] for x in et_by_cve[r["id"]]); m[(r["ev"][:1], ks.most_common(1)[0][0])] += 1
for k, v in sorted(m.items(), key=lambda x: -x[1])[:14]: print("    pilot class", k[0], "| ET", k[1], "|", v)
json.dump([{k: r.get(k) for k in ("id", "year", "pilot", "ev", "det", "picked_seen", "has_et_rule", "path_shared")} for r in R], open("research/data/summary3.json", "w"))
