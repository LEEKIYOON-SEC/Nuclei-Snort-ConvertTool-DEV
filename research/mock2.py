import sys, json, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HOST, PORT, LOG = sys.argv[1], int(sys.argv[2]), sys.argv[3]
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _do(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        with open(LOG, "a") as f:
            f.write(json.dumps({"t": time.time(), "client": self.client_address[0], "method": self.command, "uri": self.path,
                                "ctype": self.headers.get("Content-Type", ""), "body": body[:4096].decode("latin1")}) + "\n")
        out = b"ok"
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_OPTIONS = do_PATCH = do_PROPFIND = do_MOVE = do_COPY = do_TRACE = do_DEBUG = _do
    def log_message(self, *a): pass
ThreadingHTTPServer((HOST, PORT), H).serve_forever()
