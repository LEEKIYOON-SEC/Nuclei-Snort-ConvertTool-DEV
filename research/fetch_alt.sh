#!/bin/bash
# Download metadata of other candidate sources into <workdir>/alt (tree listings only for the git repos).
# usage: fetch_alt.sh <workdir>   then: venv/bin/python -I research/alt_sources.py
W=$(realpath "${1:?workdir}"); mkdir -p $W/alt; cd $W/alt
f() { mkdir -p $1; echo "$1: http=$(curl -sSL -m 120 -o $1/data -w '%{http_code}' "$2") bytes=$(stat -c %s $1/data)"; }
f etindex https://rules.emergingthreats.net/open/
f msf https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json
f edb https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv
f kev https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
f sslbl_ja3 https://sslbl.abuse.ch/blacklist/ja3_fingerprints.rules
f feodo https://feodotracker.abuse.ch/downloads/feodotracker.rules
f urlhaus https://urlhaus.abuse.ch/downloads/ids/
f threatfox https://threatfox.abuse.ch/downloads/threatfox_suricata.rules
t() { mkdir -p $1; git clone -q --depth 1 --filter=blob:none --no-checkout https://github.com/$2 $1/repo && git -C $1/repo ls-tree -r --name-only HEAD > $1/tree.txt; echo "$1: $(wc -l < $1/tree.txt) files"; }
t afrog zan8in/afrog; t xray chaitin/xray; t vulhub vulhub/vulhub; t bchecks PortSwigger/BChecks; t pocgh nomi-sec/PoC-in-GitHub
mkdir -p crs && git clone -q --depth 1 https://github.com/coreruleset/coreruleset crs/repo
