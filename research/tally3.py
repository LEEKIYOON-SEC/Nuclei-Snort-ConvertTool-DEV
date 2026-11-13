"""Join captures, engine alerts, pilot rules and ET rules into one record per template."""
import json, os, re, sys, urllib.parse as up
from collections import Counter, defaultdict
CAP = sys.argv[1] if len(sys.argv) > 1 else "cap3"; PIL = sys.argv[2] if len(sys.argv) > 2 else "pilot3"
T = json.load(open("research/data/templates.json"))
meta = {os.path.basename(m["path"])[:-5].upper(): m for m in json.load(open(PIL + "/meta.json"))}
sid2tid = {m["sid"]: t for t, m in meta.items()}
et_cves = defaultdict(set); et_msg = {}
for line in open("et/emerging-all.rules", errors="replace"):
    if not line.startswith("alert"): continue
    s = re.search(r"\bsid:\s*(\d+)", line); m = re.search(r'msg:\s*"([^"]*)"', line)
    if not s: continue
    sid = int(s.group(1)); et_msg[sid] = m.group(1) if m else ""
    for y, n in re.findall(r"(?i)cve[-_, ]{0,2}((?:19|20)\d{2})[-_.](\d{4,7})", line): et_cves[sid].add("CVE-%s-%s" % (y, n))
cves_with_et = {c for v in et_cves.values() for c in v}
PH = {"203.0.113.5": "A", "203.0.113.6": "B"}
SN = re.compile(r"\[1:(\d+):\d+\].*\{TCP\} ([\d.]+):\d+ ->")
def snort_alerts(path):
    out = defaultdict(set)
    try:
        for l in open(path, errors="replace"):
            m = SN.search(l)
            if m: out[int(m.group(1))].add(PH.get(m.group(2), "?"))
    except FileNotFoundError: return None
    return out
def num(path, pat):
    try: m = re.search(pat, open(path, errors="replace").read(), re.M)
    except FileNotFoundError: return None
    return int(m.group(1)) if m else None
def rc(path):
    try: return int(open(path).read().strip())
    except Exception: return None
rows = []
for tid in sorted(os.listdir(CAP)):
    d = f"{CAP}/{tid}"; key = tid.upper(); t = T.get(key, {}); m = meta.get(key, {})
    reqs = [json.loads(l) for l in open(d + "/req.jsonl")]
    for r in reqs: r["ph"] = PH.get(r["client"], "?")
    row = dict(id=key, year=t.get("year"), severity=t.get("severity"), tags=t.get("tags", []), n_def=t.get("nreq"), flow=t.get("flow"), oast=t.get("oast"),
               reqA=sum(r["ph"] == "A" for r in reqs), reqB=sum(r["ph"] == "B" for r in reqs), has_et_rule=key in cves_with_et,
               pilot="converted" if m and "skip" not in m else (m.get("skip") if m else "missing"), sid=m.get("sid"))
    # suricata
    sa = defaultdict(lambda: dict(ph=set(), tx=set(), urls=set())); http_ev = None
    if os.path.exists(d + "/suri/eve.json"):
        http_ev = 0
        for l in open(d + "/suri/eve.json"):
            e = json.loads(l)
            if e.get("event_type") == "http": http_ev += 1
            elif e.get("event_type") == "alert":
                a = sa[e["alert"]["signature_id"]]; a["ph"].add(PH.get(e.get("src_ip"), PH.get(e.get("dest_ip"), "?")))
                a["tx"].add((e.get("flow_id"), e.get("tx_id"))); a["urls"].add((e.get("http") or {}).get("url", "")[:200])
    row["suri_http"] = http_ev
    s2 = snort_alerts(d + "/s2.out"); s3 = snort_alerts(d + "/s3.out")
    row["s2_rc"] = rc(d + "/s2.rc"); row["s3_rc"] = rc(d + "/s3.rc")
    row["s2_http"] = num(d + "/s2.err", r"HTTP Request Headers extracted:\s+(\d+)"); row["s3_http"] = num(d + "/s3.out", r"^\s+requests: (\d+)")
    own = m.get("sid")
    row["det"] = dict(suri=sorted(sa[own]["ph"]) if own in sa else [], s2=sorted(s2[own]) if s2 and own in s2 else [], s3=sorted(s3[own]) if s3 and own in s3 else [])
    # cross fires of pilot rules (rule of another template alerting on this template's traffic)
    row["cross"] = dict(suri=sorted(sid2tid[s] for s in sa if s in sid2tid and s != own), s2=sorted(sid2tid[s] for s in (s2 or {}) if s in sid2tid and s != own),
                        s3=sorted(sid2tid[s] for s in (s3 or {}) if s in sid2tid and s != own))
    # ET alerts
    ded = [s for s in sa if s in et_cves and key in et_cves[s]]; oth = [s for s in sa if s in et_msg and s not in ded]
    row["et_dedicated"] = [(s, et_msg[s][:90]) for s in ded]; row["et_other"] = [(s, et_msg[s][:90]) for s in oth]
    row["et_ded_same_tx_as_pilot"] = bool(own in sa and any(sa[s]["tx"] & sa[own]["tx"] for s in ded)) if ded else None
    row["et_ded_urls"] = sorted({u for s in ded for u in sa[s]["urls"]})[:3]; row["pilot_urls"] = sorted(sa[own]["urls"])[:3] if own in sa else []
    # was the picked request seen on the wire at all?
    if row["pilot"] == "converted":
        row["picked"] = dict(i=m["picked"], n=m["nreq"], method=m["method"], uri=m["uri"], U=m["uri_contents"], B=m["body_contents"])
        def seen(r): return r["method"] == m["method"] and all(c in up.unquote(r["uri"]) or c in r["uri"] for c in m["uri_contents"])
        row["picked_seen"] = sorted({r["ph"] for r in reqs if seen(r)})
    rows.append(row)
json.dump(rows, open("research/data/results3.json", "w"))
print("templates:", len(rows))
# ---- harness health
bad = Counter()
for r in rows:
    n = r["reqA"] + r["reqB"]
    if n == 0: bad["no request captured"] += 1; continue
    if r["suri_http"] is None: bad["suricata: no output"] += 1
    elif r["suri_http"] < n: bad["suricata parsed fewer requests than mock logged"] += 1
    if r["s2_rc"] != 0: bad["snort2 rc!=0 or missing"] += 1
    elif (r["s2_http"] or 0) < n: bad["snort2 parsed fewer requests than mock logged"] += 1
    if r["s3_rc"] != 0: bad["snort3 rc!=0 or missing"] += 1
    elif (r["s3_http"] or 0) < n: bad["snort3 parsed fewer requests than mock logged"] += 1
print("harness health:", dict(bad))
