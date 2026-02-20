import os, sys, socket, threading, ssl, select, json, argparse, time, re, logging, subprocess, shutil, base64, urllib.parse

#logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(process)s] [%(levelname)s] %(message)s")
#logg = logging.getLogger(__name__)


# ---------------- LOGGING ----------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(process)s] [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("proxy.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
logg = logging.getLogger(__name__)


BACKLOG = 50
MAX_CHUNK_SIZE = 16*1024
BLACKLISTED = []

AUTH_USERS = {}
AUTH_FILE_PATH = None

# ---------------- STATIC RESPONSES ----------------
class StaticResponse:
    connection_established = b"HTTP/1.1 200 Connection Established\r\n\r\n"
    block_response = b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<html><body><h1>Access denied</h1></body></html>"
    auth_required = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm='Proxy'\r\nConnection: close\r\n\r\n"
    manager_auth_required = b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm='Manager'\r\nConnection: close\r\n\r\n"

# ---------------- AUTH ----------------
def load_auth_file(path: str | None):
    global AUTH_USERS, AUTH_FILE_PATH
    AUTH_FILE_PATH = path
    if not path:
        AUTH_USERS = {}
        logg.info("Auth disabled")
        return
    try:
        if not os.path.exists(path):
            AUTH_USERS = {}
            with open(path, "w") as f:
                json.dump(AUTH_USERS, f)
        else:
            with open(path, "r") as f:
                AUTH_USERS = json.load(f)
        logg.info(f"Auth enabled using: {path}")
    except Exception as e:
        logg.error(f"Failed to load auth file: {e}")
        AUTH_USERS = {}

def save_auth_file():
    if AUTH_FILE_PATH:
        try:
            with open(AUTH_FILE_PATH,"w") as f:
                json.dump(AUTH_USERS,f,indent=2)
        except Exception as e:
            logg.error(f"Failed to save auth file: {e}")

def check_proxy_auth(headers: dict) -> (bool,str):
    if AUTH_FILE_PATH is None:
        return True,None
    auth = headers.get("proxy-authorization")
    if not auth or not auth.lower().startswith("basic "):
        return False,None
    try:
        decoded = base64.b64decode(auth.split()[1]).decode()
        username,password = decoded.split(":",1)
        user = AUTH_USERS.get(username)
        if user and user.get("password")==password:
            return True, username
    except Exception:
        pass
    return False,None

def check_manager_auth(headers: dict) -> str:
    auth = headers.get("authorization")
    if not auth or not auth.lower().startswith("basic "):
        return None
    try:
        decoded = base64.b64decode(auth.split()[1]).decode()
        username,password = decoded.split(":",1)
        user = AUTH_USERS.get(username)
        if user and user.get("password")==password and user.get("admin"):
            return username
    except Exception:
        pass
    return None

# ---------------- REQUEST ----------------
class Request:
    def __init__(self, raw: bytes):
        self.raw = raw
        self.raw_split = raw.split(b"\r\n")
        try:
            self.method,self.path,self.protocol = self.raw_split[0].decode(errors="ignore").split(" ")
        except ValueError:
            self.method,self.path,self.protocol="","",""
        self.host=None
        self.port=80
        raw_host = re.findall(rb"host: (.*?)\r\n", raw.lower())
        if raw_host:
            raw_host = raw_host[0].decode()
            if ":" in raw_host:
                self.host,p = raw_host.split(":")
                self.port=int(p)
            else:
                self.host=raw_host
        if self.path.startswith("http://") or self.path.startswith("https://"):
            proto,rest=self.path.split("://",1)
            self.port = 443 if proto=="https" else 80
            host_part = rest.split("/")[0]
            if ":" in host_part:
                self.host,p=host_part.split(":")
                self.port=int(p)
            else:
                self.host=host_part
            self.path="/"+"/".join(rest.split("/")[1:])

    def header(self):
        headers = {}
        for line in self.raw_split[1:]:
            if not line: continue
            parts=line.decode(errors="ignore").split(":",1)
            if len(parts)==2:
                headers[parts[0].lower()]=parts[1].strip()
        return headers

def parse_post_body(raw: bytes):
    try:
        body = raw.split(b"\r\n\r\n",1)[1].decode()
        parsed = urllib.parse.parse_qs(body)
        return {k:v[0] for k,v in parsed.items()}
    except Exception:
        return {}

# ---------------- MANAGER ----------------
def manager_page():
    # Charge le HTML
    try:
        with open("manager.html","r",encoding="utf-8") as f:
            html_template = f.read()
    except Exception:
        return b"HTTP/1.1 500 Internal Server Error\r\n\r\nErreur lecture manager.html"

    # Injecte les utilisateurs
    rows=""
    for user,info in sorted(AUTH_USERS.items()):
        checked = "checked" if info.get("admin") else ""
        rows+=f"""
        <tr>
            <td>{user}</td>
            <td>
                <form method="POST" action="/manager/delete">
                    <input type="hidden" name="username" value="{user}">
                    <button type="submit">Supprimer</button>
                </form>
            </td>
            <td>
                <form method="POST" action="/manager/admin">
                    <input type="hidden" name="username" value="{user}">
                    <input type="checkbox" name="admin" value="1" {checked} onchange="this.form.submit()">
                    Admin
                </form>
            </td>
        </tr>
        """

    # Lit les logs depuis un fichier
    log_text=""
    log_file="proxy.log"  # même fichier où logging écrit
    if os.path.exists(log_file):
        try:
            with open(log_file,"r",encoding="utf-8",errors="ignore") as f:
                # On prend les dernières 100 lignes
                log_text = "".join(f.readlines()[-100:])
        except Exception:
            log_text="Erreur lecture du fichier de logs"

    html = html_template.replace("{{USER_ROWS}}", rows).replace("{{LOGS}}", log_text)
    return b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n" + html.encode("utf-8")

# ---------------- CERTBOT ----------------
def ensure_certbot_cert(domain):
    base = f"/etc/letsencrypt/live/{domain}"
    fullchain = f"{base}/fullchain.pem"
    privkey = f"{base}/privkey.pem"
    if os.path.exists(fullchain) and os.path.exists(privkey):
        logg.info(f"Certbot certificate found for {domain}")
        return fullchain,privkey
    if not shutil.which("certbot"):
        raise RuntimeError("certbot is not installed")
    logg.info(f"Generating Let's Encrypt certificate for {domain}")
    subprocess.check_call([
        "certbot","certonly","--standalone","--non-interactive","--agree-tos","--register-unsafely-without-email","-d",domain
    ])
    return fullchain,privkey

def run_certbot_forever():
    def loop():
        while True:
            try:
                subprocess.call(["certbot","renew","--quiet"])
            except Exception as e:
                logg.warning(f"Certbot renew error: {e}")
            time.sleep(12*3600)
    threading.Thread(target=loop,daemon=True).start()

# ---------------- CONNECTION HANDLER ----------------
class ConnectionHandle(threading.Thread):
    def __init__(self,conn,addr,debug=False):
        super().__init__(daemon=True)
        self.client_conn = conn
        self.client_addr = addr
        self.debug = debug

    def run(self):
        try:
            rawreq = self.client_conn.recv(MAX_CHUNK_SIZE)
            if not rawreq: return
            req=Request(rawreq)
            headers=req.header()

            # -------- MANAGER --------
            admin_user = check_manager_auth(headers)
            if req.path.startswith("/manager"):
                if not admin_user:
                    self.client_conn.send(StaticResponse.manager_auth_required)
                    return
                if req.method=="GET" and req.path.rstrip("/")=="/manager":
                    self.client_conn.send(manager_page())
                    return
                if req.method=="POST" and req.path=="/manager/add":
                    data=parse_post_body(rawreq)
                    u=data.get("username")
                    p=data.get("password")
                    admin_flag = data.get("admin")=="1"
                    if u and p:
                        AUTH_USERS[u]={"password":p,"admin":admin_flag}
                        save_auth_file()
                    self.client_conn.send(b"HTTP/1.1 302 Found\r\nLocation: /manager\r\n\r\n")
                    return
                if req.method=="POST" and req.path=="/manager/delete":
                    data=parse_post_body(rawreq)
                    u=data.get("username")
                    if u in AUTH_USERS:
                        AUTH_USERS.pop(u)
                        save_auth_file()
                    self.client_conn.send(b"HTTP/1.1 302 Found\r\nLocation: /manager\r\n\r\n")
                    return
                if req.method=="POST" and req.path=="/manager/admin":
                    data=parse_post_body(rawreq)
                    u=data.get("username")
                    if u in AUTH_USERS:
                        AUTH_USERS[u]["admin"]=data.get("admin")=="1"
                        save_auth_file()
                    self.client_conn.send(b"HTTP/1.1 302 Found\r\nLocation: /manager\r\n\r\n")
                    return

            # -------- PROXY --------
            ok,user = check_proxy_auth(headers)
            if not ok:
                self.client_conn.send(StaticResponse.auth_required)
                return
            if req.host in BLACKLISTED:
                self.client_conn.send(StaticResponse.block_response)
                return

            server_conn=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            try:
                server_conn.connect((req.host,req.port))
            except Exception:
                self.client_conn.send(b"HTTP/1.1 503 Service Unavailable\r\n\r\n")
                return

            if req.method.upper()=="CONNECT":
                self.client_conn.send(StaticResponse.connection_established)
            else:
                server_conn.send(rawreq)

            while True:
                ready=select.select([self.client_conn,server_conn],[],[],60)[0]
                if not ready: break
                if self.client_conn in ready:
                    data=self.client_conn.recv(MAX_CHUNK_SIZE)
                    if not data: break
                    server_conn.send(data)
                if server_conn in ready:
                    data=server_conn.recv(MAX_CHUNK_SIZE)
                    if not data: break
                    self.client_conn.send(data)

        except Exception as e:
            logg.exception(f"[{self.client_addr}] error: {e}")
        finally:
            try: self.client_conn.close()
            except: pass

# ---------------- PROXY SERVER ----------------
class ProxyServer:
    def __init__(self,host,port,tls_ctx=None,debug=False):
        self.tls_ctx = tls_ctx
        self.debug = debug
        sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        sock.bind((host,port))
        sock.listen(BACKLOG)
        self.sock=sock
        proto="https" if tls_ctx else "http"
        logg.info(f"Proxy listening at {proto}://{host}:{port}")

    def start(self):
        while True:
            conn,addr=self.sock.accept()
            if self.tls_ctx:
                try:
                    conn=self.tls_ctx.wrap_socket(conn,server_side=True)
                except ssl.SSLError:
                    conn.close()
                    continue
            ConnectionHandle(conn,addr,debug=self.debug).start()

# ---------------- MAIN ----------------
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--host",default="0.0.0.0")
    parser.add_argument("--http-port",type=int,default=8080)
    parser.add_argument("--tls-port",type=int,default=8443)
    parser.add_argument("--tls",action="store_true")
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--certbot-domain")
    parser.add_argument("--auth-file")
    parser.add_argument("--no-auth",action="store_true")
    args=parser.parse_args()

    if args.no_auth:
        load_auth_file(None)
    else:
        load_auth_file(args.auth_file or "auth.json")

    tls_ctx=None
    cert_path=args.cert
    key_path=args.key

    if args.certbot_domain:
        cert_path,key_path=ensure_certbot_cert(args.certbot_domain)
        run_certbot_forever()

    if args.tls:
        if not (cert_path and key_path):
            logg.error("TLS enabled but no certificate provided")
            sys.exit(1)
        tls_ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_ctx.load_cert_chain(certfile=cert_path,keyfile=key_path)
        logg.info("TLS enabled")

    # start HTTP
    threading.Thread(target=lambda: ProxyServer(args.host,args.http_port).start(),daemon=True).start()
    # start TLS
    if args.tls:
        ProxyServer(args.host,args.tls_port,tls_ctx=tls_ctx).start()
    else:
        while True: time.sleep(3600)

if __name__=="__main__":
    main()
