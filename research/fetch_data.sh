#!/bin/bash
# Download the inputs of the comparison into <workdir>. usage: fetch_data.sh <workdir>
set -e
W=$(realpath "${1:?workdir}"); mkdir -p $W/nt $W/et $W/src/c29 $W/src/c3; cd $W
[ -d nt/nuclei-templates ] || git clone --depth 1 -q https://github.com/projectdiscovery/nuclei-templates nt/nuclei-templates
[ -d nt/hist ] || git clone -q --filter=blob:none --no-checkout https://github.com/projectdiscovery/nuclei-templates nt/hist   # history only, for add dates
curl -sS -m 180 -o et/emerging-all.rules https://rules.emergingthreats.net/open/suricata-7.0.3/emerging-all.rules
curl -sS -m 180 -o src/et-snort29.rules https://rules.emergingthreats.net/open/snort-2.9.0/emerging-all.rules
curl -sSL -m 180 https://www.snort.org/downloads/community/community-rules.tar.gz | tar xz -C src/c29
curl -sSL -m 180 https://www.snort.org/downloads/community/snort3-community-rules.tar.gz | tar xz -C src/c3
[ -d src/sigma ] || git clone --depth 1 -q https://github.com/SigmaHQ/sigma src/sigma
mkdir -p research/data
git -C nt/hist log --first-parent -m --no-renames --diff-filter=A --name-only --format='@%cI' HEAD -- '*.yaml' > research/data/adds.raw
ls nt/nuclei-templates/http/cves/2024/*.yaml nt/nuclei-templates/http/cves/2025/*.yaml nt/nuclei-templates/http/cves/2026/*.yaml > all3.list
find nt/nuclei-templates/http/technologies nt/nuclei-templates/http/exposed-panels -name '*.yaml' | sort > probe.list
