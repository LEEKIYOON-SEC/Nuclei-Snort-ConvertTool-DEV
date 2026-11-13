"""Mechanical template copy that lets nuclei send every request offline:
drop flow/matchers/extractors, replace the OAST placeholder with a literal, and
list the variables that would have come from earlier responses or from outside."""
import sys, re, yaml
BUILTIN = {"BaseURL", "RootURL", "Hostname", "Host", "Port", "Path", "File", "Scheme", "FQDN", "RDN", "DN", "TLD", "SD", "randstr", "true", "false", "nil", "interactsh", "url"}
OAST = "oast.example.test"
def walk(o, f):
    if isinstance(o, str): return f(o)
    if isinstance(o, list): return [walk(x, f) for x in o]
    if isinstance(o, dict): return {k: walk(v, f) for k, v in o.items()}
    return o
def deoast(s):
    s = s.replace("{{interactsh-url}}", OAST)
    return re.sub(r"\{\{[^{}]*\}\}", lambda m: re.sub(r"interactsh-url(_\d+)?", "'%s'" % OAST, m.group(0)), s)
def names_in(s, defined):
    out = set()
    for expr in re.findall(r"\{\{([^{}]*)\}\}", s):
        e = re.sub(r"'[^']*'|\"[^\"]*\"", " ", expr)
        for m in re.finditer(r"[A-Za-z_][A-Za-z0-9_]*", e):
            n = m.group(0)
            if e[m.end():m.end() + 1] == "(" or n in BUILTIN or n in defined or re.fullmatch(r"randstr_\d+", n): continue
            if m.start() > 0 and (e[m.start() - 1].isdigit() or e[m.start() - 1] in ".-"): continue
            out.add(n)
    return out
def main(src, dst):
    t = yaml.safe_load(open(src)); t.pop("flow", None)
    t = walk(t, deoast); defined = set((t.get("variables") or {}).keys()); need = set()
    for b in t.get("http") or []:
        if not isinstance(b, dict): continue
        for k in ("extractors", "matchers", "matchers-condition", "stop-at-first-match"): b.pop(k, None)
        b["matchers"] = [{"type": "status", "status": [599]}]
        b["skip-variables-check"] = True
        d = defined | set((b.get("payloads") or {}).keys())
        strs = []
        walk({k: v for k, v in b.items() if k in ("raw", "path", "body", "headers")}, lambda s: strs.append(s) or s)
        for s in strs: need |= names_in(s, d)
    for v in (t.get("variables") or {}).values():
        if isinstance(v, str): need |= names_in(v, defined)
    yaml.safe_dump(t, open(dst, "w"), sort_keys=False, width=100000, allow_unicode=True)
    print(" ".join("-var %s=abc123" % n for n in sorted(need)))
if __name__ == "__main__": main(sys.argv[1], sys.argv[2])
