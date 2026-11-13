#!/bin/bash
# usage: snort_batch.sh <capdir> <rulesdir>   -> per pcap: s2.out/s2.rc (Snort 2.9) and s3.out/s3.rc (Snort 3)
S=$(dirname "$(realpath "$0")")/..; S=$(realpath $S); C=$(realpath $1); RU=$(realpath $2)
ls $C | xargs -P 4 -I{} sh -c "d=$C/{}; [ \$(stat -c %s \$d/cap.pcap) -gt 24 ] || exit 0; mkdir -p \$d/s2tmp; cd \$d/s2tmp; snort -c $S/conf/snort2.conf -S TESTRULES=$RU/snort2.rules -r \$d/cap.pcap -k none -A console -l . --pid-path . > \$d/s2.out 2> \$d/s2.err; echo \$? > \$d/s2.rc; cd ..; rm -rf \$d/s2tmp"
echo "snort2 done: $(ls $C/*/s2.rc | wc -l)"
docker run --rm --network none -v $C:/c -v $RU:/p snort3 sh -c '
run() { for d in "$@"; do [ $(stat -c %s $d/cap.pcap) -gt 24 ] || continue; snort -c /etc/snort/snort.lua -R /p/snort3.rules -r $d/cap.pcap -k none -A alert_fast > $d/s3.out 2>&1; echo $? > $d/s3.rc; done; }
set -- /c/*; n=$#; q=$(( (n + 3) / 4 )); i=0; a=""; b=""; c=""; e=""
for d in "$@"; do case $(( i / q )) in 0) a="$a $d";; 1) b="$b $d";; 2) c="$c $d";; *) e="$e $d";; esac; i=$((i+1)); done
run $a & run $b & run $c & run $e & wait'
echo "snort3 done: $(ls $C/*/s3.rc | wc -l)"
