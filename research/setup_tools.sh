#!/bin/bash
# Rebuild the verification tools in a fresh cloud session. usage: setup_tools.sh <workdir>
# Installs Suricata 7.0.3, Snort 2.9.20, tcpdump (apt), nuclei v3.11.1 (go), sigma-cli (venv), Snort 3.9.2.0 (Docker/Alpine).
set -e
W=$(realpath "${1:?workdir}"); R=$(dirname "$(realpath "$0")"); mkdir -p $W/bin $W/conf $W/s3img /var/run/suricata
apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq suricata snort tcpdump > $W/apt.log 2>&1
[ -x $W/bin/nuclei ] || GOBIN=$W/bin go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1 > $W/go.log 2>&1
[ -x $W/venv/bin/sigma ] || { python3 -m venv $W/venv; $W/venv/bin/pip install -q sigma-cli pysigma-backend-sqlite > $W/pip.log 2>&1; }
# Snort 2.9 test config: the packaged snort.conf with its rule includes replaced by one variable include
sed -E 's|^include \$RULE_PATH.*|# &|' /etc/snort/snort.conf > $W/conf/snort2.conf; echo 'include $TESTRULES' >> $W/conf/snort2.conf
cp /etc/snort/classification.config /etc/snort/reference.config /etc/snort/unicode.map /etc/snort/threshold.conf $W/conf/
docker ps > /dev/null 2>&1 || { (nohup dockerd > $W/dockerd.log 2>&1 &); sleep 8; }
if ! docker image inspect snort3 > /dev/null 2>&1; then
  cp /root/.ccr/ca-bundle.crt $W/s3img/; cp $R/snort3.Dockerfile $W/s3img/Dockerfile
  docker build -q --network host --build-arg HTTPS_PROXY=$HTTPS_PROXY --build-arg HTTP_PROXY=${HTTP_PROXY:-$HTTPS_PROXY} -t snort3 $W/s3img
fi
suricata -V; snort -V 2>&1 | grep Version; docker run --rm --network none snort3 snort -V 2>&1 | grep Version; $W/bin/nuclei -version 2>&1 | grep Engine; $W/venv/bin/sigma version
