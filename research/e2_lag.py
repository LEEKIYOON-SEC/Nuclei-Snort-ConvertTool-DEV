import json, re, os, statistics as st
from datetime import date
from collections import Counter, defaultdict
T = json.load(open("research/data/templates.json")); R = json.load(open("research/data/rules_with_cve.json"))
first = {}; cur = None
for line in open("research/data/adds.raw"):
    line = line.strip()
    if line.startswith("@"): cur = line[1:11]; continue
    m = re.search(r"(CVE-\d{4}-\d+)\.yaml$", line, re.I)
    if m and "/http/" in "/" + line or (m and line.startswith("cves/")):
        c = m.group(1).upper()
        if c not in first or cur < first[c]: first[c] = cur
json.dump(first, open("research/data/template_added.json", "w"))
D = lambda s: date(*map(int, s.split("-")))
snap = max(first.values()); print("templates with add date:", sum(c in first for c in T), "of", len(T), "| history up to", snap)
def earliest(k, c, enabled_only=True):
    ds = [r["created"] for r in R[k] if c in r["cves"] and r.get("created") and (r["enabled"] or not enabled_only)]
    return min(ds) if ds else None
print("\n== lag = (ET rule created) - (nuclei template added), days; + means nuclei first")
for y in (2021, 2022, 2023, 2024, 2025, 2026):
    lags = []
    for c, t in T.items():
        if t["year"] != y or c not in first: continue
        e = earliest("et_suri", c)
        if e: lags.append((D(e) - D(first[c])).days)
    if not lags: continue
    lags.sort(); n = len(lags)
    print(f"{y}: overlap={n:3d} nuclei_first={sum(l > 0 for l in lags):3d} same_day={sum(l == 0 for l in lags):2d} ET_first={sum(l < 0 for l in lags):3d} | median={st.median(lags):+.0f}d  p25={lags[n//4]:+d} p75={lags[3*n//4]:+d} | ET first by >7d: {sum(l < -7 for l in lags)}, nuclei first by >7d: {sum(l > 7 for l in lags)}")
print("\n== templates still without any enabled ET rule, by template age at snapshot")
for y in (2024, 2025, 2026):
    ages = defaultdict(lambda: [0, 0])
    for c, t in T.items():
        if t["year"] != y or c not in first: continue
        age = (D(snap) - D(first[c])).days; b = "<30d" if age < 30 else "30-90d" if age < 90 else "90-365d" if age < 365 else ">=365d"
        ages[b][0] += 1; ages[b][1] += earliest("et_suri", c) is not None
    print(y, {b: f"{v[1]}/{v[0]} covered" for b, v in sorted(ages.items())})
print("\n== coverage by attribute, 2024-2026 (enabled ET suricata rule exists)")
def cov(pred, label):
    ids = [c for c, t in T.items() if t["year"] >= 2024 and pred(t)]; k = sum(earliest("et_suri", c) is not None for c in ids)
    print(f"  {label:28s} {k:4d}/{len(ids):4d} = {100*k/max(1,len(ids)):.0f}%")
cov(lambda t: True, "all")
for s in ("critical", "high", "medium"): cov(lambda t, s=s: t["severity"] == s, "severity " + s)
cov(lambda t: "kev" in t["tags"], "tag kev (CISA KEV)"); cov(lambda t: "vkev" in t["tags"] and "kev" not in t["tags"], "tag vkev only"); cov(lambda t: "kev" not in t["tags"] and "vkev" not in t["tags"], "neither kev nor vkev")
cov(lambda t: "wordpress" in t["tags"] or "wp-plugin" in t["tags"] or "wp" in t["tags"], "wordpress"); cov(lambda t: not ("wordpress" in t["tags"] or "wp-plugin" in t["tags"] or "wp" in t["tags"]), "non-wordpress")
for tag in ("rce", "sqli", "xss", "lfi", "auth-bypass", "ssrf", "file-upload", "exposure", "authenticated", "unauth"): cov(lambda t, tag=tag: tag in t["tags"], "tag " + tag)
print("\n== KEV-tagged templates 2024-2026: lag where both exist")
lags = sorted((D(earliest("et_suri", c)) - D(first[c])).days for c, t in T.items() if t["year"] >= 2024 and "kev" in t["tags"] and c in first and earliest("et_suri", c))
print("  n=%d nuclei_first=%d ET_first=%d median=%+.0f" % (len(lags), sum(l > 0 for l in lags), sum(l < 0 for l in lags), st.median(lags)))
print("\n== sigma lag (rule date - template added), all years")
lags = sorted((D(earliest("sigma", c)) - D(first[c])).days for c in T if c in first and earliest("sigma", c) and re.match(r"\d{4}-\d\d-\d\d", earliest("sigma", c)))
print("  n=%d nuclei_first=%d sigma_first=%d median=%+.0f" % (len(lags), sum(l > 0 for l in lags), sum(l < 0 for l in lags), st.median(lags)))
print("\ntemplates added per month (last 14):", sorted(Counter(first[c][:7] for c in T if c in first).items())[-14:])
