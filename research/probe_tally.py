"""False-positive proxy: which rules alert on non-attack probe traffic (technology / login-panel detection templates)?"""
import json, os, re
from collections import Counter, defaultdict
meta = {m["sid"]: os.path.basename(m["path"])[:-5].upper() for m in json.load(open("pilot3/meta.json")) if "skip" not in m}
S3 = {x["id"]: x for x in json.load(open("research/data/summary3.json"))}
et = {x["sid"]: x for x in json.load(open("research/data/et_rules_for_nuclei_cves.json"))}
fires = defaultdict(set); urls = defaultdict(Counter); nreq = 0; npc = 0; nhttp = 0; noeve = 0
for d in sorted(os.listdir("capb")):
    rq = sum(1 for _ in open(f"capb/{d}/req.jsonl")); nreq += rq
    p = f"capb/{d}/suri/eve.json"
    if not os.path.exists(p):
        noeve += rq > 0; continue
    npc += 1
    for l in open(p):
        e = json.loads(l)
        if e.get("event_type") == "http": nhttp += 1
        elif e.get("event_type") == "alert":
            sid = e["alert"]["signature_id"]; fires[sid].add(d); urls[sid][(e.get("http") or {}).get("http_method", "") + " " + (e.get("http") or {}).get("url", "")[:60]] += 1
print(f"probe templates replayed: {npc} | requests logged by mock: {nreq} | http transactions parsed by Suricata: {nhttp} | captures with requests but no engine output: {noeve}")
pil = {s: v for s, v in fires.items() if s in meta}; etf = {s: v for s, v in fires.items() if s in et}
print(f"pilot rules loaded: {len(meta)} | alerted on probe traffic: {len(pil)} ({100*len(pil)/len(meta):.1f}%) | on >=5 probe templates: {sum(len(v) >= 5 for v in pil.values())}")
print(f"ET rules for the same CVEs loaded: {len(et)} | alerted on probe traffic: {len(etf)} ({100*len(etf)/len(et):.1f}%)")
print("pilot rules firing, by class:", dict(Counter(S3[meta[s]]["ev"][:1] for s in pil)), "| class sizes:", dict(Counter(x["ev"][:1] for x in S3.values() if x.get("ev"))))
print("top pilot rules by number of probe templates hit:")
for s, v in sorted(pil.items(), key=lambda x: -len(x[1]))[:14]: print(f"  {len(v):4d}  {meta[s]}  class {S3[meta[s]]['ev'][:1]}  e.g. {urls[s].most_common(1)[0][0]}")
print("ET rules firing on probe traffic:")
for s, v in sorted(etf.items(), key=lambda x: -len(x[1]))[:8]: print(f"  {len(v):4d}  {s} {et[s]['msg'][:70]} | {et[s]['kind']} | e.g. {urls[s].most_common(1)[0][0]}")
json.dump({"pilot": {meta[s]: sorted(v) for s, v in pil.items()}, "et": {str(s): sorted(v) for s, v in etf.items()}}, open("research/data/probe_fires.json", "w"))
