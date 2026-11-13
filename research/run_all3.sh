#!/bin/bash
S=$(dirname "$(realpath "$0")")/..; cd $S; S=$(pwd)
until [ cap3.end -nt cap3.start ]; do sleep 5; done
echo "capture finished: $(ls cap3 | wc -l) dirs, $(( $(cat cap3.end) - $(cat cap3.start) ))s"
/usr/bin/python3 research/suri_batch.py $S/pilot3/et_plus_pilot.rules cap3 suri etwork0 0/2 > etwork0.log 2>&1 &
/usr/bin/python3 research/suri_batch.py $S/pilot3/et_plus_pilot.rules cap3 suri etwork1 1/2 > etwork1.log 2>&1 &
research/snort_batch.sh cap3 pilot3 > snortbatch.log 2>&1 &
wait
tail -2 etwork0.log etwork1.log snortbatch.log
venv/bin/python research/tally3.py cap3 pilot3
