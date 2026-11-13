"""Minimal Suricata rule option parser (enough to describe what a rule matches on)."""
import re
OPT = re.compile(r"\s*((?:[^;\\]|\\.)*);")
LEGACY = {"http_uri": "http.uri", "http_raw_uri": "http.uri.raw", "http_client_body": "http.request_body", "http_header": "http.header", "http_raw_header": "http.header.raw",
          "http_method": "http.method", "http_cookie": "http.cookie", "http_user_agent": "http.user_agent", "http_host": "http.host", "http_stat_code": "http.stat_code",
          "http_server_body": "http.response_body", "http_stat_msg": "http.stat_msg", "http_raw_host": "http.host.raw"}
def unhex(s):
    out = bytearray(); i = 0
    while i < len(s):
        if s[i] == "|":
            j = s.index("|", i + 1); out += bytes.fromhex(s[i + 1:j].replace(" ", "")); i = j + 1
        elif s[i] == "\\" and i + 1 < len(s): out += s[i + 1].encode(); i += 2
        else: out += s[i].encode("utf-8", "replace"); i += 1
    return bytes(out)
def parse(rule):
    m = re.match(r"\s*#?\s*(\w+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*\((.*)\)\s*$", rule, re.S)
    if not m: return None
    r = dict(action=m.group(1), proto=m.group(2), header=" ".join(m.group(i) for i in range(3, 8)), contents=[], pcre=[], opts={}, buffers=[])
    cur = "payload"
    for om in OPT.finditer(m.group(8)):
        o = om.group(1).strip()
        if not o: continue
        k, _, v = o.partition(":"); k = k.strip(); v = v.strip()
        if k == "content":
            neg = v.startswith("!"); q = re.search(r'"(.*)"', v, re.S)
            try: b = unhex(q.group(1)) if q else b""
            except Exception: b = (q.group(1) if q else "").encode()
            r["contents"].append(dict(buf=cur, neg=neg, bytes=b, mods=[]))
        elif k == "pcre":
            flags = v.rsplit("/", 1)[-1].strip('"') if "/" in v else ""
            buf = cur
            for f, bname in (("U", "http.uri"), ("P", "http.request_body"), ("H", "http.header"), ("I", "http.uri.raw"), ("C", "http.cookie"), ("M", "http.method"), ("Q", "http.response_body")):
                if f in flags and cur == "payload": buf = bname
            r["pcre"].append(dict(buf=buf, v=v))
        elif k in LEGACY and r["contents"]: r["contents"][-1]["buf"] = LEGACY[k]
        elif ("." in k and not v and k not in ("file.name",)) or k in ("file_data", "pkt_data", "http_request_line", "http_header_names", "http_content_type", "http_accept", "http_referer", "http_start", "http_protocol", "http_content_len", "http_response_line", "base64_data", "dns_query", "tls_sni"):
            cur = k; r["buffers"].append(k)
        elif k in ("nocase", "fast_pattern", "startswith", "endswith", "depth", "offset", "distance", "within", "isdataat", "bsize") and r["contents"]: r["contents"][-1]["mods"].append(k)
        else: r["opts"].setdefault(k, []).append(v)
    return r
RESP = ("http.stat_code", "http.response_body", "file_data", "file.data", "http.stat_msg", "http.server", "http.location", "http.response_line", "http.server_body")
def shape(r):
    flow = ",".join(r["opts"].get("flow", []))
    side = "response" if ("to_client" in flow or "from_server" in flow) else "request"
    pos = [c for c in r["contents"] if not c["neg"]]
    bufs = {c["buf"] for c in pos} | {p["buf"] for p in r["pcre"]}
    core = bufs - {"http.method"}
    if side == "response" or any(b in RESP for b in bufs): kind = "response-side"
    elif core <= {"http.uri", "http.uri.raw"} and core: kind = "uri-only" + ("+pcre" if r["pcre"] else "")
    elif "http.request_body" in core: kind = "uri+body" + ("+pcre" if r["pcre"] else "") if core & {"http.uri", "http.uri.raw"} else "body-only" + ("+pcre" if r["pcre"] else "")
    elif core & {"http.header", "http.header.raw", "http.cookie", "http.user_agent", "http.host", "http.header_names", "http.content_type", "http.request_line", "http.start", "http.referer", "http.accept"}: kind = "uri+header" if core & {"http.uri", "http.uri.raw"} else "header-only"
    elif core <= {"payload"}: kind = "raw-payload"
    else: kind = "other:" + ",".join(sorted(core))
    return dict(side=side, kind=kind, n_content=len(pos), content_bytes=sum(len(c["bytes"]) for c in pos), n_pcre=len(r["pcre"]), bufs=sorted(bufs),
                flowbits=bool(r["opts"].get("flowbits")), threshold=bool(r["opts"].get("threshold")))
