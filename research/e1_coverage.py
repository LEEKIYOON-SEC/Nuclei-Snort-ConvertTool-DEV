import sys, os, re, glob, json, yaml
from collections import Counter, defaultdict
sys.path.insert(0, os.path.dirname(__file__)); sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rulesets import parse_rules, parse_sigma
import pilot
S = "."
src = dict(et_suri=parse_rules("et/emerging-all.rules", "et_suri"), et_snort29=parse_rules("src/et-snort29.rules", "et_snort29"),
           comm29=parse_rules("src/c29/community-rules/community.rules", "comm29"), comm3=parse_rules("src/c3/snort3-community-rules/snort3-community.rules", "comm3"),
           sigma=parse_sigma("src/sigma"))
for k, v in src.items():
    print(f"{k:11s} rules={len(v):6d} enabled={sum(r['enabled'] for r in v):6d} with_cve={sum(bool(r['cves']) for r in v):5d} distinct_cves={len({c for r in v for c in r['cves']})}")
print("sigma webserver/proxy categories:", Counter((r.get("category"), r.get("product")) for r in src["sigma"] if r["cves"]).most_common(8))
# nuclei templates
L = getattr(yaml, "CSafeLoader", yaml.SafeLoader); T = {}
for p in sorted(glob.glob("nt/nuclei-templates/http/cves/*/*.yaml")):
    try: t = yaml.load(open(p), Loader=L)
    except Exception as e: print("yaml fail", p); continue
    info = t.get("info") or {}; tags = [x.strip() for x in str(info.get("tags") or "").split(",") if x.strip()]
    txt = open(p).read(); reqs = pilot.requests_of(t)
    cid = os.path.basename(p)[:-5].upper()
    T[cid] = dict(path=os.path.relpath(p, "nt/nuclei-templates"), year=int(p.split("/")[-2]), severity=str(info.get("severity")), tags=tags,
                  nreq=len(reqs), flow=bool(re.search(r"^flow:", txt, re.M)), oast="interactsh" in txt, body=any(r["body"] for r in reqs),
                  extvar=bool(re.search(r"\{\{(username|password)\}\}", txt)))
cov = {k: defaultdict(list) for k in src}
for k, v in src.items():
    for r in v:
        for c in r["cves"]: cov[k][c].append(r)
def has(k, c, enabled=True, http=False):
    return any((r["enabled"] or not enabled) and (not http or r.get("proto") in ("http", "http1", "http2")) for r in cov[k].get(c, []))
print("\nyear  nuclei | ET-suri(en) ET-suri(+disabled) ET-snort29(en) | comm29 comm3 | sigma | any(enabled)")
tot = Counter()
for y in sorted({t["year"] for t in T.values()}):
    ids = [c for c, t in T.items() if t["year"] == y]
    row = dict(n=len(ids), es=sum(has("et_suri", c) for c in ids), esd=sum(has("et_suri", c, False) for c in ids), e29=sum(has("et_snort29", c) for c in ids),
               c29=sum(has("comm29", c) for c in ids), c3=sum(has("comm3", c) for c in ids), sg=sum(has("sigma", c) for c in ids),
               anyc=sum(any(has(k, c) for k in src) for c in ids))
    tot.update(row)
    if y >= 2017: print(f"{y}  {row['n']:5d} | {row['es']:5d} {row['esd']:5d} {row['e29']:5d} | {row['c29']:4d} {row['c3']:4d} | {row['sg']:4d} | {row['anyc']:5d} ({100*row['anyc']/row['n']:.0f}%)")
print("ALL  ", dict(tot))
print("\ntop tags 2024-2026:", Counter(x for t in T.values() if t["year"] >= 2024 for x in t["tags"]).most_common(70))
print("severity 2024-2026:", Counter(t["severity"] for t in T.values() if t["year"] >= 2024))
json.dump(T, open("research/data/templates.json", "w"))
slim = {k: [{kk: vv for kk, vv in r.items() if kk != "raw"} for r in v if r["cves"]] for k, v in src.items()}
json.dump(slim, open("research/data/rules_with_cve.json", "w"))
