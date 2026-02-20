Start 
python3 server.py --tls --certbot-domain  DOMAIN --tls-port TLS PORT --auth-file auth.json --http-port HTTP PORT


If you use different HTTP port certbot will run with 80 


usage: server.py [-h] [--host HOST] [--http-port HTTP_PORT] [--tls-port TLS_PORT] [--tls] [--cert CERT] [--key KEY] [--certbot-domain CERTBOT_DOMAIN] [--auth-file AUTH_FILE] [--no-auth]

options:
  -h, --help            show this help message and exit
  --host HOST
  --http-port HTTP_PORT
  --tls-port TLS_PORT
  --tls
  --cert CERT
  --key KEY
  --certbot-domain CERTBOT_DOMAIN
  --auth-file AUTH_FILE
  --no-auth
