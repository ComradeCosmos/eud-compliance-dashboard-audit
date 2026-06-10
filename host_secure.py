import os
import sys
import ssl
import http.server
import socketserver
import subprocess
import argparse
import json
import base64
from datetime import datetime
import excel_validator

# Secure HTTP Request Handler
class SecureRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Serve strictly from the frontend/ subdirectory
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'frontend'))
        super().__init__(*args, directory=base_dir, **kwargs)

    def end_headers(self):
        # Inject GRC Hardening Security Headers (relaxed framing to support embedding on other sites)
        # self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
        self.send_header('Content-Security-Policy', "default-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; frame-ancestors *;")
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.send_header('Permissions-Policy', 'geolocation=(), camera=(), microphone=()')
        super().end_headers()

    def translate_path(self, path):
        # Prevent directory traversal attacks
        translated = super().translate_path(path)
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'frontend'))
        if not os.path.abspath(translated).startswith(base_dir):
            sys.stderr.write(f"[WARNING] Directory traversal attempt detected: {path}\n")
            return os.path.join(base_dir, 'index.html')
        return translated

    def log_message(self, format, *args):
        # Structured console logging for GRC/SIEM audits
        log_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        sys.stderr.write(f"[{log_time}] {self.client_address[0]} - {format%args}\n")

    def do_POST(self):
        if self.path == '/api/validate-sheet':
            self.handle_validate_sheet()
        elif self.path == '/api/reconcile-sheets':
            self.handle_reconcile_sheets()
        else:
            self.send_error(404, "API endpoint not found")

    def send_json_response(self, data, status=200):
        try:
            response_bytes = json.dumps(data).encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response_bytes)))
            self.end_headers()
            self.wfile.write(response_bytes)
        except Exception as e:
            sys.stderr.write(f"[ERROR] Failed to send JSON response: {e}\n")

    def handle_validate_sheet(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            req_json = json.loads(post_data.decode('utf-8'))
            
            filename = req_json.get('filename', '')
            base64_content = req_json.get('content', '')
            
            file_bytes = base64.b64decode(base64_content)
            
            if filename.lower().endswith('.xlsx'):
                rows = excel_validator.parse_xlsx(file_bytes)
            else:
                rows = excel_validator.parse_csv(file_bytes.decode('utf-8', errors='ignore'))
                
            if not rows or len(rows) < 2:
                self.send_json_response({
                    "success": False,
                    "message": "Incompatible empty or corrupted file template."
                })
                return
                
            headers = rows[0]
            data_rows = rows[1:]
            
            report = excel_validator.validate_sheet_data(headers, data_rows)
            
            self.send_json_response({
                "success": True,
                "filename": filename,
                "headers": headers,
                "rows": rows,
                "validation_report": report
            })
            
        except Exception as e:
            self.send_json_response({
                "success": False,
                "message": f"Server-side parsing failed: {str(e)}"
            })

    def handle_reconcile_sheets(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            req_json = json.loads(post_data.decode('utf-8'))
            
            sheets = req_json.get('sheets', [])
            if len(sheets) < 2:
                self.send_json_response({
                    "success": False,
                    "message": "Reconciliation requires at least two sheets."
                })
                return
                
            primary_sheet = None
            secondary_sheets = []
            for sheet in sheets:
                if sheet.get('role') == 'primary':
                    primary_sheet = sheet
                else:
                    secondary_sheets.append(sheet)
                    
            if not primary_sheet or not secondary_sheets:
                self.send_json_response({
                    "success": False,
                    "message": "Deep reconciliation requires 1 Primary and at least 1 Secondary sheet."
                })
                return
                
            results = excel_validator.reconcile_sheets_data(primary_sheet, secondary_sheets)
            
            self.send_json_response({
                "success": True,
                "results": results
            })
            
        except Exception as e:
            self.send_json_response({
                "success": False,
                "message": f"Server-side reconciliation failed: {str(e)}"
            })


def generate_self_signed_cert(cert_path, key_path):
    print("[Certificate Manager] Generating new self-signed SSL/TLS certificates...")
    openssl_path = "openssl"
    
    # Check if standard "openssl" is available in PATH
    try:
        subprocess.run([openssl_path, "version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except (subprocess.SubprocessError, FileNotFoundError):
        # Fallback to Git's OpenSSL on Windows
        git_openssl = r"C:\Program Files\Git\usr\bin\openssl.exe"
        if os.path.exists(git_openssl):
            openssl_path = git_openssl
        else:
            sys.stderr.write("[ERROR] OpenSSL is not installed or not in the PATH. Cannot auto-generate certificates.\n")
            sys.stderr.write("Please generate certificates manually: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes\n")
            return False
            
    try:
        # Run openssl command to generate key and self-signed certificate
        cmd = [
            openssl_path, "req", "-x509", "-newkey", "rsa:4096",
            "-keyout", key_path, "-out", cert_path,
            "-sha256", "-days", "365", "-nodes",
            "-subj", "/C=US/ST=State/L=City/O=Organization/OU=IT/CN=localhost"
        ]
        subprocess.run(cmd, check=True)
        print(f"[Certificate Manager] Successfully generated {cert_path} and {key_path}!")
        return True
    except Exception as e:
        sys.stderr.write(f"[ERROR] Failed to run openssl command: {e}\n")
        return False


def main():
    parser = argparse.ArgumentParser(description="Secure Corporate Network Hosting Server for EUD Dashboard")
    parser.add_argument("--port", type=int, help="Port to bind the server to (default: 4430 for HTTPS, 8080 for HTTP)")
    parser.add_argument("--bind", default="127.0.0.1", help="Interface to bind to (default: 127.0.0.1 for local isolation)")
    parser.add_argument("--cert", default="cert.pem", help="Path to SSL certificate file (default: cert.pem)")
    parser.add_argument("--key", default="key.pem", help="Path to SSL private key file (default: key.pem)")
    parser.add_argument("--generate-cert", action="store_true", help="Auto-generate self-signed cert if missing")
    parser.add_argument("--no-ssl", action="store_true", help="Disable HTTPS encryption (runs in plain HTTP - NOT recommended for production)")

    args = parser.parse_args()

    # Prioritize dynamic PORT environment variable (injected by AWS/cloud services)
    port_env = os.environ.get('PORT')
    if port_env:
        try:
            args.port = int(port_env)
        except ValueError:
            sys.stderr.write(f"[WARNING] Invalid PORT environment variable '{port_env}'. Using defaults.\n")

    # Determine default port
    if args.port is None:
        args.port = 8080 if args.no_ssl else 4430

    print("================================================================================")
    print("                 [SECURE] CORPORATE COMPLIANCE HOSTING ENGINE")
    print("================================================================================")

    # Configure Socket Server
    handler = SecureRequestHandler
    socketserver.TCPServer.allow_reuse_address = True

    try:
        with socketserver.TCPServer((args.bind, args.port), handler) as httpd:
            if args.no_ssl:
                print(f"[SECURITY WARNING] RUNNING SERVER IN UNENCRYPTED PLAIN HTTP MODE!")
                print(f"[Security Notice] Bind Address: http://{args.bind}:{args.port}")
                print("--------------------------------------------------------------------------------")
            else:
                # SSL/TLS Setup
                cert_exists = os.path.exists(args.cert) and os.path.exists(args.key)
                if not cert_exists:
                    if args.generate_cert:
                        success = generate_self_signed_cert(args.cert, args.key)
                        if not success:
                            sys.exit(1)
                    else:
                        sys.stderr.write(f"[ERROR] SSL credentials not found at {args.cert} or {args.key}.\n")
                        sys.stderr.write("Use --generate-cert to auto-generate them, or --no-ssl to run without encryption.\n")
                        sys.exit(1)

                # Wrap server socket with SSL context
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(certfile=args.cert, keyfile=args.key)
                httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

                print(f"[SSL/TLS ACTIVE] HTTP Strict Transport Security (HSTS) and Secure Socket Layer enabled.")
                print(f"[Security Info] Bind Address: https://{args.bind}:{args.port}")
                print(f"[Security Info] Loaded Cert: {args.cert}")
                print("--------------------------------------------------------------------------------")

            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Server started successfully. Press Ctrl+C to terminate.")
            httpd.serve_forever()

    except KeyboardInterrupt:
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Shutting down server gracefully...")
    except Exception as e:
        sys.stderr.write(f"[FATAL ERROR] Failed to start server: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
