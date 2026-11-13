"""Rough yield estimate from the pilot: how many templates end up with strong / uncertain / unusable evidence."""
import json
from collections import Counter
R = json.load(open("research/data/results3.json")); S3 = {x["id"]: x for x in json.load(open("research/data/summary3.json"))}
PF = json.load(open("research/data/probe_fires.json"))["pilot"]
cross = {o for r in R for e in ("suri", "s2", "s3") for o in r["cross"][e]}
def tier(r):
    if r["pilot"] != "converted": return "F pilot made no rule (%s)" % r["pilot"]
    ev = S3[r["id"]]["ev"][0]; n3 = sum(bool(r["det"][e]) for e in ("suri", "s2", "s3"))
    if r["id"] in cross or r["id"] in PF or ev == "4": return "D alerts on unrelated traffic, or path-only on a shared endpoint"
    if n3 < 3: return "E not confirmed in all three engines (%s)" % ("attack request never sent" if not r["picked_seen"] else "engine-specific mismatch")
    if ev == "3": return "C path-only rule on an endpoint unique to the template"
    return ("A" if r["picked"]["n"] == 1 else "B") + " endpoint+parameter/payload evidence, confirmed in 3 engines, " + ("single request" if r["picked"]["n"] == 1 else "multi-request (attack-request pick must be right)")
c = Counter(tier(r) for r in R)
for k, v in sorted(c.items()): print(f"  {v:5d}  {100*v/len(R):5.1f}%  {k}")
for y in (2024, 2025, 2026):
    sub = [r for r in R if r["year"] == y]; cc = Counter(tier(r)[0] for r in sub); print("  ", y, {k: "%.0f%%" % (100 * v / len(sub)) for k, v in sorted(cc.items())})
no_et = [r for r in R if not r["has_et_rule"]]; cc = Counter(tier(r)[0] for r in no_et)
print("  CVEs without any ET rule (n=%d):" % len(no_et), {k: v for k, v in sorted(cc.items())})
silent = [r for r in R if not r["et_dedicated"] and not [m for s, m in r["et_other"] if not m.startswith(("ET INFO", "ET POLICY", "ET HUNTING"))] and r["reqA"] + r["reqB"] > 0]
cc = Counter(tier(r)[0] for r in silent); print("  templates where full ET Open stayed silent (n=%d):" % len(silent), {k: v for k, v in sorted(cc.items())})
