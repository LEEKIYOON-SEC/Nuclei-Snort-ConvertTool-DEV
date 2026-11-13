#!/bin/bash
# usage: capture_a.sh <template> <outdir>   -- original template only (used for non-attack "probe" templates)
T=$(realpath "$1"); mkdir -p "$2"; O=$(realpath "$2"); R=$(dirname "$(realpath "$0")"); S=$R/..; N=$S/bin/nuclei
rm -f $O/cap.pcap $O/req.jsonl $O/a.out
unshare -n env -u HTTPS_PROXY -u HTTP_PROXY -u https_proxy -u http_proxy bash -c "
ip link set lo up; ip addr add 192.168.56.10/32 dev lo; ip addr add 203.0.113.5/32 dev lo
ip route replace local 192.168.56.10 dev lo table local src 203.0.113.5
python3 $R/mock2.py 192.168.56.10 80 $O/req.jsonl & M=\$!
tcpdump -i lo --immediate-mode -U -w $O/cap.pcap tcp port 80 2>/dev/null & D=\$!
sleep 0.8
timeout 40 $N -t $T -u http://192.168.56.10 -duc -ni -nc -timeout 3 -retries 0 -var username=admin -var password=admin123 < /dev/null > $O/a.out 2>&1
sleep 1.2; kill -INT \$D; kill \$M; wait \$D 2>/dev/null
"
touch $O/req.jsonl
