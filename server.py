import os, sys, socket, threading, ssl, select, json, argparse, time, re, logging, subprocess, shutil, base64

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(process)s] [%(levelname)s] %(message)s")
logg = logging.getLogger(__name__)

BACKLOG = 50
MAX_CHUNK_SIZE = 16 * 1024
BLACKLISTED = []
AUTH_USERS = None

# ---------------- STATIC RESPONSES ----------------
class StaticResponse:
    connection_established = b"HTTP/1.1 200 Connection Established\r\n\r\n"
    block_response = b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<html><body><h1>Access denied</h1></body></html>"
    auth_required = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=Proxy\r\nConnection: close\r\n\r\n"

# ---------------- ERRORS ----------------
class Error:
    STATUS_503 = "Service Unavailable"
    STATUS_505 = "HTTP Version Not Supported"

for key in filter(lambda x: x.startswith("STATUS"), dir(Error)):
    _, code = key.split("_")
    value = getattr(Error, f"STATUS_{code}")
    setattr(Error, f"STATUS_{code}", f"HTTP/1.1 {code} {value}\r\n\r\n".encode())

# ---------------- AUTH ----------------
def load_auth_file(path: str | None):
    global AUTH_USERS
    if not path:
        AUTH_USERS = None
        logg.info("Auth disabled")
        return
    try:
        with open(path, "r") as f:
            AUTH_USERS = json.load(f)
        logg.info(f"Auth enabled using: {path}")
    except Exception as e:
        logg.error(f"Failed to load auth file: {e}")
        AUTH_USERS = None

def check_auth(headers: dict) -> bool:
    if AUTH_USERS is None:
        return True
    auth = headers.get("proxy-authorization")
    if not auth or not auth.lower().startswith("basic "):
        return False
    try:
        decoded = base64.b64decode(auth.split()[1]).decode()
        username, password = decoded.split(":",1)
        return AUTH_USERS.get(username) == password
    except Exception:
        return False

# ---------------- REQUEST ----------------
class Request:
    def __init__(self, raw: bytes):
        self.raw = raw
        self.raw_split = raw.split(b"\r\n")
        self.log = self.raw_split[0].decode(errors="ignore")
        try:
            self.method, self.path, self.protocol = self.log.split(" ")
        except ValueError:
            self.method, self.path, self.protocol = "", "", ""
        self.host = None
        self.port = 80

        raw_host = re.findall(rb"host: (.*?)\r\n", raw.lower())
        if raw_host:
            raw_host = raw_host[0].decode()
            if ":" in raw_host:
                self.host, p = raw_host.split(":")
                self.port = int(p)
            else:
                self.host = raw_host

        if self.path.startswith("http://") or self.path.startswith("https://"):
            proto, rest = self.path.split("://",1)
            self.port = 443 if proto=="https" else 80
            host_part = rest.split("/")[0]
            if ":" in host_part:
                self.host, p = host_part.split(":")
                self.port = int(p)
            else:
                self.host = host_part
            self.path = "/" + "/".join(rest.split("/")[1:])

    def header(self):
        headers = {}
        for line in self.raw_split[1:]:
            if not line:
                continue
            parts = line.decode(errors="ignore").split(":",1)
            if len(parts)==2:
                headers[parts[0].lower()] = parts[1].strip()
        return headers

# ---------------- RESPONSE ----------------
class Response:
    def __init__(self, raw: bytes):
        try:
            self.protocol, self.status, self.status_str = raw.split(b"\r\n",1)[0].decode().split(" ")
        except Exception:
            self.protocol, self.status, self.status_str = "", "", ""

# ---------------- CONNECTION HANDLER ----------------
class ConnectionHandle(threading.Thread):
    def __init__(self, conn, addr, debug=False):
        super().__init__(daemon=True)
        self.client_conn = conn
        self.client_addr = addr
        self.debug = debug

    def run(self):
        try:
            rawreq = self.client_conn.recv(MAX_CHUNK_SIZE)
            if not rawreq:
                logg.debug(f"[{self.client_addr}] Empty request received, closing.")
                return

            req = Request(rawreq)
            headers = req.header()
            if self.debug: logg.info(f"[{self.client_addr}] {req.method} {req.path} {req.protocol} Host: {req.host}:{req.port}")

            # --- AUTH ---
            if not check_auth(headers):
                self.client_conn.send(StaticResponse.auth_required)
                logg.info(f"[{self.client_addr}] 407 Proxy Authentication Required for {req.host}")
                return

            # --- BLACKLIST ---
            if req.host in BLACKLISTED:
                self.client_conn.send(StaticResponse.block_response)
                logg.info(f"[{self.client_addr}] Blocked host {req.host}")
                return

            server_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                server_conn.connect((req.host, req.port))
                if self.debug: logg.info(f"[{self.client_addr}] Connected to {req.host}:{req.port}")
            except Exception:
                self.client_conn.send(Error.STATUS_503)
                logg.warning(f"[{self.client_addr}] Failed to connect to {req.host}:{req.port}")
                return

            if req.method.upper() == "CONNECT":
                self.client_conn.send(StaticResponse.connection_established)
                if self.debug: logg.info(f"[{self.client_addr}] CONNECT tunnel established to {req.host}:{req.port}")
            else:
                server_conn.send(rawreq)
                if self.debug: logg.info(f"[{self.client_addr}] Sent initial request to {req.host}:{req.port}")

            # --- DATA TRANSIT LOOP ---
            while True:
                ready = select.select([self.client_conn, server_conn], [], [], 60)[0]
                if not ready:
                    logg.debug(f"[{self.client_addr}] Timeout, closing connection")
                    break

                if self.client_conn in ready:
                    data = self.client_conn.recv(MAX_CHUNK_SIZE)
                    if not data:
                        logg.debug(f"[{self.client_addr}] Client closed connection")
                        break
                    if self.debug: logg.info(f"[{self.client_addr}] C->S {req.host}:{req.port} {len(data)} bytes")
                    server_conn.send(data)

                if server_conn in ready:
                    data = server_conn.recv(MAX_CHUNK_SIZE)
                    if not data:
                        logg.debug(f"[{self.client_addr}] Server closed connection {req.host}:{req.port}")
                        break
                    if self.debug: logg.info(f"[{self.client_addr}] S->{req.host}:{req.port} {len(data)} bytes")
                    self.client_conn.send(data)

        except Exception as e:
            logg.exception(f"[{self.client_addr}] Connection error: {e}")
        finally:
            try: self.client_conn.close()
            except: pass

# ---------------- PROXY SERVER ----------------
class ProxyServer:
    def __init__(self, host, port, tls_ctx=None, debug=False):
        self.tls_ctx = tls_ctx
        self.debug = debug
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(BACKLOG)
        self.sock = sock
        proto = "https" if tls_ctx else "http"
        logg.info(f"Proxy listening at: {proto}://{host}:{port}")

    def start(self):
        while True:
            conn, addr = self.sock.accept()
            if self.tls_ctx:
                try:
                    conn = self.tls_ctx.wrap_socket(conn, server_side=True)
                except ssl.SSLError:
                    logg.warning(f"[{addr}] TLS handshake failed")
                    conn.close()
                    continue
            ConnectionHandle(conn, addr, debug=self.debug).start()

# ---------------- CERTBOT ----------------
def ensure_certbot_cert(domain):
    base = f"/etc/letsencrypt/live/{domain}"
    fullchain = f"{base}/fullchain.pem"
    privkey = f"{base}/privkey.pem"
    if os.path.exists(fullchain) and os.path.exists(privkey):
        logg.info(f"Certbot certificate found for {domain}")
        return fullchain, privkey
    if not shutil.which("certbot"):
        raise RuntimeError("certbot is not installed")
    logg.info(f"Generating Let's Encrypt certificate for {domain} (port 80 must be free)...")
    subprocess.check_call([
        "certbot", "certonly", "--standalone", "--non-interactive",
        "--agree-tos", "--register-unsafely-without-email", "-d", domain
    ])
    return fullchain, privkey

def run_certbot_forever():
    def loop():
        while True:
            try:
                subprocess.call(["certbot", "renew", "--quiet"])
            except Exception as e:
                logg.warning(f"Certbot renew error: {e}")
            time.sleep(12*3600)
    threading.Thread(target=loop, daemon=True).start()

# ---------------- MAIN ----------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--http-port", type=int, default=8080, help="HTTP proxy port")
    parser.add_argument("--tls-port", type=int, default=8443, help="TLS proxy port")
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--certbot-domain", help="Auto obtain Let's Encrypt cert (port 80 must be free)")
    parser.add_argument("--auth-file")
    parser.add_argument("--no-auth", action="store_true")
    parser.add_argument("--debug-transit", action="store_true")
    args = parser.parse_args()

    if args.no_auth:
        load_auth_file(None)
    else:
        load_auth_file(args.auth_file)

    tls_ctx = None
    cert_path = args.cert
    key_path = args.key

    if args.certbot_domain:
        try:
            cert_path, key_path = ensure_certbot_cert(args.certbot_domain)
            run_certbot_forever()
        except Exception as e:
            logg.error(f"Certbot failed: {e}")
            sys.exit(1)

    if args.tls:
        if not (cert_path and key_path):
            logg.error("TLS enabled but no certificate provided")
            sys.exit(1)
        try:
            tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            logg.info("TLS enabled")
        except Exception as e:
            logg.error(f"TLS setup failed: {e}")
            sys.exit(1)

    # HTTP proxy
    threading.Thread(target=lambda: ProxyServer(args.host, args.http_port, debug=args.debug_transit).start(), daemon=True).start()

    # TLS proxy
    if args.tls:
        ProxyServer(args.host, args.tls_port, tls_ctx=tls_ctx, debug=args.debug_transit).start()

if __name__=="__main__":
    main()
root@proxy:/o