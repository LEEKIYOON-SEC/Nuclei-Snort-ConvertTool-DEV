#!/bin/bash
S=$(dirname "$(realpath "$0")")/..; cd $S; S=$(pwd)
while read t; do id=$(basename $t .yaml); [ -f capb/$id/req.jsonl ] || echo $t; done < probe.list > probe.rest
cat probe.rest | xargs -P 6 -I{} sh -c 'id=$(basename {} .yaml); research/capture_a.sh {} capb/$id >/dev/null 2>&1'
echo "probe capture done: $(ls capb | wc -l)"
/usr/bin/python3 research/suri_batch.py $S/pilot3/probe.rules capb suri probework0 0/2 > probework0.log 2>&1 &
/usr/bin/python3 research/suri_batch.py $S/pilot3/probe.rules capb suri probework1 1/2 > probework1.log 2>&1 &
wait; cat probework0.log probework1.log | tail -4; echo PROBE-DONE
