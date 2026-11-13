"""Parse public rulesets into per-rule records (CVE refs, dates, buffers)."""
import re, os, glob, yaml
CVE = re.compile(r"(?i)cve[-_, ]{0,2}((?:19|20)\d{2})[-_.](\d{4,7})")
def cves_in(s): return sorted({"CVE-%s-%s" % m for m in CVE.findall(s)})
def md(line, key):
    m = re.search(r"\b%s (\d{4})_(\d{2})_(\d{2})" % key, line); return "-".join(m.groups()) if m else None
def mdv(line, key):
    m = re.search(r"\b%s ([A-Za-z_]+)" % key, line); return m.group(1) if m else None
def parse_rules(path, source):
    out = []
    for line in open(path, errors="replace"):
        m = re.match(r"\s*(#\s*)?(alert|drop|pass|reject)\s+(\S+)\s", line)
        if not m: continue
        sid = re.search(r"\bsid:\s*(\d+)", line); msg = re.search(r'msg:\s*"([^"]*)"', line)
        out.append(dict(source=source, enabled=not m.group(1), proto=m.group(3), sid=int(sid.group(1)) if sid else None,
                        msg=msg.group(1) if msg else "", cves=cves_in(line), created=md(line, "created_at"), updated=md(line, "updated_at"),
                        confidence=mdv(line, "confidence"), severity=mdv(line, "signature_severity"), raw=line.strip()))
    return out
def parse_sigma(root):
    out = []
    for p in glob.glob(root + "/rules*/**/*.yml", recursive=True):
        try: d = yaml.safe_load(open(p))
        except Exception: continue
        if not isinstance(d, dict): continue
        text = " ".join(map(str, d.get("tags") or [])) + " " + os.path.basename(p) + " " + str(d.get("title", ""))
        ls = d.get("logsource") or {}
        out.append(dict(source="sigma", enabled=True, path=os.path.relpath(p, root), cves=cves_in(text), created=str(d.get("date") or "")[:10] or None,
                        category=ls.get("category"), product=ls.get("product"), service=ls.get("service")))
    return out
