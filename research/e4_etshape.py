import json, sys, os, re, statistics as st
from collections import Counter, defaultdict
sys.path.insert(0, os.path.dirname(__file__))
from rulesets import parse_rules; import ruleparse
T = json.load(open("research/data/templates.json")); ids = {c for c, t in T.items() if t["year"] >= 2024}
rules = [r for r in parse_rules("et/emerging-all.rules", "et_suri") if r["enabled"] and set(r["cves"]) & ids]
print("enabled ET rules referencing a 2024-2026 nuclei http CVE:", len(rules), "| CVEs:", len({c for r in rules for c in r["cves"] if c in ids}))
rows = []
for r in rules:
    p = ruleparse.parse(r["raw"])
    if not p: print("parse fail", r["sid"]); continue
    rows.append(dict(sid=r["sid"], msg=r["msg"], cves=[c for c in r["cves"] if c in ids], proto=p["proto"], header=p["header"], confidence=r["confidence"], severity=r["severity"],
                     classtype=(p["opts"].get("classtype") or [""])[0], created=r["created"], **ruleparse.shape(p),
                     uri_contents=[c["bytes"].decode("latin1") for c in p["contents"] if c["buf"] in ("http.uri", "http.uri.raw") and not c["neg"]],
                     body_contents=[c["bytes"].decode("latin1") for c in p["contents"] if c["buf"] == "http.request_body" and not c["neg"]]))
json.dump(rows, open("research/data/et_rules_for_nuclei_cves.json", "w"), indent=0)
C = lambda f: Counter(f(x) for x in rows).most_common(12)
print("proto:", C(lambda x: x["proto"])); print("header:", C(lambda x: x["header"])[:6])
print("msg prefix:", C(lambda x: " ".join(x["msg"].split()[:2]))); print("classtype:", C(lambda x: x["classtype"]))
print("confidence:", C(lambda x: x["confidence"])); print("signature_severity:", C(lambda x: x["severity"]))
print("kind:", C(lambda x: x["kind"]))
req = [x for x in rows if x["side"] == "request" and x["kind"] != "response-side" and x["proto"].startswith("http")]
print("request-side http rules:", len(req), "| flowbits:", sum(x["flowbits"] for x in req), "| threshold:", sum(x["threshold"] for x in req))
for k in ("uri-only", "uri-only+pcre", "uri+body", "uri+body+pcre", "uri+header", "body-only", "body-only+pcre"):
    xs = [x for x in req if x["kind"] == k]
    if xs: print(f"  {k:15s} n={len(xs):3d} contents median={st.median(x['n_content'] for x in xs):.0f} bytes median={st.median(x['content_bytes'] for x in xs):.0f} (min {min(x['content_bytes'] for x in xs)})  conf={dict(Counter(x['confidence'] for x in xs))}")
print("\nsample uri-only rules (what professionals accept as path-only):")
for x in [x for x in req if x["kind"] == "uri-only"][:14]: print("  ", x["sid"], x["confidence"], "|", x["msg"][:70], "|", x["uri_contents"])
