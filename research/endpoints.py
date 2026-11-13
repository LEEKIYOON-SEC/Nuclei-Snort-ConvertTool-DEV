"""How many different templates request the same path? (data-driven list of 'common endpoints')"""
import glob, yaml, re, sys, os, json
from collections import defaultdict, Counter
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); import pilot
L = getattr(yaml, "CSafeLoader", yaml.SafeLoader); paths = defaultdict(set); n = 0; kinds = Counter()
def norm(uri):
    p = pilot.BASE.sub("", uri).split("?")[0].split("#")[0]
    p = pilot.VAR.sub("{}", p).rstrip("/") or "/"
    return p.lower()
for f in glob.glob("nt/nuclei-templates/http/**/*.yaml", recursive=True):
    try: t = yaml.load(open(f), Loader=L)
    except Exception: continue
    if not isinstance(t, dict): continue
    n += 1; kinds[f.split("/http/")[1].split("/")[0]] += 1
    for r in pilot.requests_of(t): paths[norm(r["uri"])].add(t.get("id"))
freq = {p: len(v) for p, v in paths.items()}
json.dump(freq, open("research/data/path_freq.json", "w"))
print("http templates parsed:", n, dict(kinds.most_common(8))); print("distinct paths:", len(freq))
print("paths used by >=10 templates:", sum(v >= 10 for v in freq.values()), "| >=3:", sum(v >= 3 for v in freq.values()))
for p, v in sorted(freq.items(), key=lambda x: -x[1])[:45]: print(f"  {v:5d}  {p}")
