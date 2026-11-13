"""Pilot converter used only to measure feasibility (NOT the product): nuclei http template -> one naive rule per engine."""
import sys, re, json, yaml, random, os, urllib.parse as up
VAR = re.compile(r"\{\{[^{}]*\}\}|§[^§]*§")
BASE = re.compile(r"\{\{(BaseURL|RootURL|Hostname|Host|Port|Scheme|Path)\}\}")
GENERIC = {"/", "/index.php", "/wp-admin/admin-ajax.php", "/wp-login.php", "/login", "/api", "/admin", "/wp-json", "/index.html", "/login.php", "/xmlrpc.php"}
def requests_of(t):
    out = []
    for bi, b in enumerate(t.get("http") or t.get("requests") or []):
        if not isinstance(b, dict): continue
        for r in b.get("raw") or []:
            if not isinstance(r, str): continue
            head, _, body = r.replace("\r\n", "\n").partition("\n\n")
            lines = head.strip("\n").split("\n")
            m = re.match(r"\s*(\S+)\s+(\S.*?)\s+HTTP/[\d.]+\s*$", lines[0])
            if not m: continue
            out.append(dict(block=bi, method=m.group(1), uri=m.group(2), body=body.strip("\n"), ctype=" ".join(l for l in lines[1:] if l.lower().startswith("content-type"))))
        for p in b.get("path") or []:
            out.append(dict(block=bi, method=str(b.get("method", "GET")), uri=BASE.sub("", str(p)), body=str(b.get("body") or ""), ctype=str((b.get("headers") or {}).get("Content-Type", ""))))
    return out
def literal_vars(t):
    return {k: str(v) for k, v in (t.get("variables") or {}).items() if isinstance(v, (str, int)) and "{{" not in str(v) and "(" not in str(v)}
def subst(s, lv):
    return re.sub(r"\{\{(\w+)\}\}", lambda m: lv.get(m.group(1), m.group(0)), s)
def segs(s):
    return [x for x in VAR.split(s) if x]
def esc(s):
    return "".join(c if 32 <= ord(c) < 127 and c not in '";\\|' else "|%02X|" % b for c in s for b in ([ord(c)] if 32 <= ord(c) < 127 and c not in '";\\|' else c.encode()))[:0] or "".join((c if (32 <= ord(c) < 127 and c not in '";\\|') else "".join("|%02X|" % b for b in c.encode())) for c in s)
def convert(path, sid):
    t = yaml.safe_load(open(path)); lv = literal_vars(t); tid = t.get("id", "?")
    reqs = requests_of(t)
    if not reqs: return None, "no-http-request"
    txt = open(path).read()
    flags = dict(multi=len(reqs) > 1, flow="\nflow:" in txt, oast="interactsh" in txt, extvar=bool(re.search(r"\{\{(username|password)\}\}", txt)))
    cands = []
    for i, r in enumerate(reqs):
        uri = subst(r["uri"], lv); body = subst(r["body"], lv)
        upath = uri.split("?")[0]
        us = [up.unquote(x) for x in segs(uri)]
        us = [x for x in us if len(x) >= 4 and "/../" not in x and "/./" not in x and "//" not in x and not x.startswith("..")]
        form = "urlencoded" in r["ctype"].lower()
        bs = [y for x in segs(body) for y in x.split("\n") if len(y.strip()) >= 6]
        bs = [y.strip() for y in bs if "nuclei" not in y.lower() and not (form and re.search(r"[%+]", y))]
        bs = sorted(bs, key=len, reverse=True)[:2]
        generic = (not VAR.search(upath)) and upath.rstrip("/") in {g.rstrip("/") for g in GENERIC}
        score = sum(len(x) for x in us) * (0.2 if generic else 1) + sum(min(len(x), 40) for x in bs)
        if generic and not bs and len(uri) < 40: score = 0
        cands.append((score, i, r, us, bs))
    score, i, r, us, bs = max(cands, key=lambda c: c[0])
    if score < 12 or (not us and not bs): return None, "weak-or-generic"
    us = [x[:60] for x in sorted(us, key=len, reverse=True)[:3]]; bs = [x[:60] for x in bs]
    msg = "NUCLEI-CONV %s" % tid; meth = r["method"] if re.fullmatch(r"[A-Z]+", r["method"]) else None
    tail = 'sid:%d; rev:1;)' % sid
    su = 'alert http any any -> any any (msg:"%s"; flow:established,to_server; ' % msg
    s2 = 'alert tcp any any -> any $HTTP_PORTS (msg:"%s"; flow:to_server,established; ' % msg
    s3 = 'alert http any any -> any any (msg:"%s"; flow:to_server,established; ' % msg
    if meth:
        su += 'http.method; content:"%s"; ' % meth; s2 += 'content:"%s"; http_method; ' % meth; s3 += 'http_method; content:"%s"; ' % meth
    if us:
        su += "http.uri; " + "".join('content:"%s"; ' % esc(x) for x in us)
        s2 += "".join('content:"%s"; http_uri; ' % esc(x) for x in us)
        s3 += "http_uri; " + "".join('content:"%s"; ' % esc(x) for x in us)
    if bs:
        su += "http.request_body; " + "".join('content:"%s"; ' % esc(x) for x in bs)
        s2 += "".join('content:"%s"; http_client_body; ' % esc(x) for x in bs)
        s3 += "http_client_body; " + "".join('content:"%s"; ' % esc(x) for x in bs)
    info = dict(id=tid, sid=sid, picked=i, nreq=len(reqs), method=r["method"], uri=r["uri"][:120], uri_contents=us, body_contents=bs, **flags)
    return dict(suri=su + tail, snort2=s2 + tail, snort3=s3 + tail, info=info), None
if __name__ == "__main__":
    lst, outdir = sys.argv[1], sys.argv[2]; os.makedirs(outdir, exist_ok=True)
    rules = dict(suri=[], snort2=[], snort3=[]); meta = []; sid = 9100000
    for p in open(lst).read().split():
        sid += 1
        try: r, why = convert(p, sid)
        except Exception as e: r, why = None, "error:" + type(e).__name__
        if r is None: meta.append(dict(path=p, sid=sid, skip=why)); continue
        for k in rules: rules[k].append(r[k])
        meta.append(dict(path=p, **r["info"]))
    for k in rules: open(f"{outdir}/{k}.rules", "w").write("\n".join(rules[k]) + "\n")
    json.dump(meta, open(f"{outdir}/meta.json", "w"), indent=1)
    from collections import Counter
    print(Counter(m.get("skip", "converted") for m in meta))
