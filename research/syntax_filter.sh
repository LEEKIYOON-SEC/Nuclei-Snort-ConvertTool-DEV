#!/bin/bash
# drop rules an engine refuses to load; record the dropped sids per engine
S=$(dirname "$(realpath "$0")")/..; D=$(realpath $1); cd $D; : > syntax_dropped.txt
suricata -T -S $D/suri.rules -l /tmp > suriT.out 2>&1; echo "suricata -T rc=$?"
grep -o 'sid:[0-9]*; rev:1;)" from file' suriT.out | grep -o '[0-9]\{7\}' | sort -u | while read s; do echo "suri $s" >> syntax_dropped.txt; sed -i "/sid:$s;/d" suri.rules; done
for i in $(seq 1 60); do
  snort -T -c $S/conf/snort2.conf -S TESTRULES=$D/snort2.rules > s2T.out 2>&1 && break
  ln=$(grep -o "snort2.rules([0-9]*)" s2T.out | head -1 | grep -o '[0-9]*' | tail -1); [ -z "$ln" ] && { echo "snort2: unknown failure"; tail -3 s2T.out; break; }
  s=$(sed -n "${ln}p" snort2.rules | grep -o 'sid:[0-9]*' | cut -d: -f2); echo "snort2 $s $(grep -m1 ERROR s2T.out | cut -c1-200 | sed 's/.*rules([0-9]*) //')" >> syntax_dropped.txt; sed -i "${ln}d" snort2.rules
done; echo "snort2 -T: $(grep -c . snort2.rules) rules kept; $(grep -E 'successfully validated' s2T.out)"
for i in $(seq 1 8); do
  docker run --rm --network none -v $D:/p snort3 snort -T -c /etc/snort/snort.lua -R /p/snort3.rules > s3T.out 2>&1 && break
  lns=$(grep -o "snort3.rules:[0-9]*" s3T.out | cut -d: -f2 | sort -rnu); [ -z "$lns" ] && { echo "snort3: unknown failure"; tail -3 s3T.out; break; }
  for ln in $lns; do s=$(sed -n "${ln}p" snort3.rules | grep -o 'sid:[0-9]*' | cut -d: -f2); echo "snort3 $s $(grep -m1 "snort3.rules:$ln " s3T.out | cut -c1-160)" >> syntax_dropped.txt; sed -i "${ln}d" snort3.rules; done
done; echo "snort3 -T: $(grep -c . snort3.rules) rules kept; $(grep -E 'successfully validated' s3T.out)"
suricata -T -S $D/suri.rules -l /tmp > suriT2.out 2>&1; echo "suricata -T (after drop) rc=$? kept=$(grep -c . suri.rules)"
cut -d' ' -f1 syntax_dropped.txt | sort | uniq -c
