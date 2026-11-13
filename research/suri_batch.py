"""Replay many pcaps through one long-lived Suricata (unix-socket mode): the ruleset loads once."""
import sys, os, json, time, subprocess, socket
sys.path.insert(0, "/usr/lib/suricata/python")
from suricata.sc import SuricataSC
rules, capdir, outname, work = sys.argv[1], os.path.abspath(sys.argv[2]), sys.argv[3], os.path.abspath(sys.argv[4])
os.makedirs(work, exist_ok=True); si, sn = map(int, (sys.argv[5] if len(sys.argv) > 5 else "0/1").split("/"))
sock = "/var/run/suricata/nconv%d.sock" % si  # unix socket paths are limited to 107 bytes
if os.path.exists(sock): os.remove(sock)
log = open(work + "/suricata.stdout", "w")
p = subprocess.Popen(["suricata", "-c", "/etc/suricata/suricata.yaml", "-S", rules, "--unix-socket=" + sock, "-k", "none", "-l", work,
                      "--set", "stream.checksum-validation=no"], stdout=log, stderr=subprocess.STDOUT)
t0 = time.time()
while not os.path.exists(sock):
    if p.poll() is not None: sys.exit("suricata exited rc=%s during startup" % p.returncode)
    time.sleep(1)
time.sleep(1); print("engine up after %.0fs" % (time.time() - t0), flush=True)
sc = SuricataSC(sock); sc.connect()
ids = sorted(d for d in os.listdir(capdir) if os.path.exists(f"{capdir}/{d}/cap.pcap") and os.path.getsize(f"{capdir}/{d}/cap.pcap") > 24)[si::sn]
for d in ids:
    o = f"{capdir}/{d}/{outname}"; subprocess.run(["rm", "-rf", o]); os.makedirs(o)
    r = sc.send_command("pcap-file", {"filename": f"{capdir}/{d}/cap.pcap", "output-dir": o})
    if r.get("return") != "OK": print("queue fail", d, r)
while True:
    n = sc.send_command("pcap-file-number")["message"]; cur = sc.send_command("pcap-current")["message"]
    if n == 0 and cur in ("None", None): break
    if p.poll() is not None: sys.exit("ENGINE DIED rc=%s with %s pcaps left" % (p.returncode, n))
    time.sleep(2)
time.sleep(2); sc.send_command("shutdown"); p.wait(timeout=120)
print("processed %d pcaps in %.0fs, engine rc=%s" % (len(ids), time.time() - t0, p.returncode))
