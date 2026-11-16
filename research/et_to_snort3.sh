#!/bin/bash
# Experiment: do ET Open rules (Snort 2.9 edition) still detect after snort2lua conversion to Snort 3?
# Needs the work directory of the earlier steps (src/et-snort29.rules, cap3/, conf/, research/data/*.json).
# The steps below were run one by one on 2026-11-16; this file records them and was not run as a whole.
# usage: et_to_snort3.sh <workdir>
S=$(realpath "${1:?workdir}"); mkdir -p $S/etconv/c2; cd $S/etconv
curl -sS -m 60 -o et_classification.config https://rules.emergingthreats.net/open/snort-2.9.0/rules/classification.config
# 1. rules ET wrote for CVEs that also have a nuclei template, and the templates to replay
$S/venv/bin/python -I - "$S" <<'PY'
import json, re, sys
S = sys.argv[1]
sids = {x["sid"] for x in json.load(open(S + "/research/data/et_rules_for_nuclei_cves.json"))}
allr = [l for l in open(S + "/src/et-snort29.rules", errors="replace") if l.startswith("alert")]
open("subset29.rules", "w").write("".join(l for l in allr if (m := re.search(r"\bsid:\s*(\d+)", l)) and int(m.group(1)) in sids))
R = [r for r in json.load(open(S + "/research/data/results3.json")) if r["has_et_rule"] and r["reqA"] + r["reqB"] > 0]
open("ids.txt", "w").write("\n".join(r["id"] for r in R))
et = [l.split(":", 1)[1].strip().split(",") for l in open("et_classification.config") if l.startswith("config classification")]
lua = "\nlocal have = {}\nfor _, c in ipairs(classifications) do have[c.name] = true end\nlocal et = {\n"
lua += "".join("  { name = '%s', priority = %d, text = '%s' },\n" % (x[0].strip(), int(x[-1]), ",".join(x[1:-1]).strip().replace("'", "")) for x in et)
lua += "}\nfor _, c in ipairs(et) do if not have[c.name] then table.insert(classifications, c) end end\n"
lua += "for _, n in ipairs({'bid', 'md5', 'arachnids', 'mcafee'}) do table.insert(references, { name = n, url = 'http://' }) end\n"
open("et_add.lua", "w").write(lua)
PY
# 2. Snort 2.9 test config that knows ET's reference systems
cp $S/conf/* c2/; printf 'config reference: bid http://\nconfig reference: md5 http://\nconfig reference: arachnids http://\nconfig reference: mcafee http://\n' >> c2/reference.config
cp c2/snort2.conf c2/snort2_et.conf
# 3. convert with the official tool, load-test converted and unconverted rules in Snort 3
docker run --rm --network none -v $S:/w snort3 sh -c '
cd /w/etconv && rm -rf s3conf && cp -r /etc/snort s3conf && cat et_add.lua >> s3conf/snort.lua
snort2lua -c subset29.rules -r subset_s3.rules -o subset.lua -e subset.rej >/dev/null 2>&1
snort2lua -c /w/src/et-snort29.rules -r full_s3.rules -o full.lua -e full.rej >/dev/null 2>&1
echo "converted: subset $(grep -c ^alert subset_s3.rules), full $(grep -c ^alert full_s3.rules)"
snort -c s3conf/snort.lua -R subset_s3.rules -T > subset_s3.T 2>&1; echo "converted subset load errors: $(grep -c "^ERROR" subset_s3.T)"
snort -c s3conf/snort.lua -R subset29.rules -T > subset_raw.T 2>&1; echo "unconverted subset load errors: $(grep -c "^ERROR" subset_raw.T)"
snort -c s3conf/snort.lua -R full_s3.rules -T > full_s3.T 2>&1; echo "converted full load errors: $(grep -c "^ERROR" full_s3.T)"'
# 4. replay the same captures: Snort 2.9 with ET's own edition, Snort 3 with the converted rules
cat ids.txt | xargs -P 4 -I{} sh -c "d=$S/cap3/{}; mkdir -p \$d/s2et; cd \$d/s2et; snort -c $S/etconv/c2/snort2_et.conf -S TESTRULES=$S/etconv/subset29.rules -r \$d/cap.pcap -k none -A console -l . --pid-path . > \$d/s2et.out 2> \$d/s2et.err; echo \$? > \$d/s2et.rc; cd ..; rm -rf \$d/s2et"
docker run --rm --network none -v $S:/w snort3 sh -c 'cd /w/etconv; for id in $(cat ids.txt); do d=/w/cap3/$id; snort -c s3conf/snort.lua -R subset_s3.rules -r $d/cap.pcap -k none -A alert_fast > $d/s3et.out 2>&1; echo $? > $d/s3et.rc; done'
# 5. compare alert SIDs per template: cap3/<id>/s2et.out, cap3/<id>/s3et.out, and et_dedicated in results3.json (Suricata)
