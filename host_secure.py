import os
import sys
import ssl
import http.server
import socketserver
import subprocess
import argparse
import json
import base64
import sqlite3
import secrets
from datetime import datetime
import excel_validator

def get_db_conn():
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database.db')
    return sqlite3.connect(db_path)

def init_db():
    try:
        conn = get_db_conn()
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                role TEXT NOT NULL,
                oauth_provider TEXT,
                created_at TEXT NOT NULL
            )
        ''')
        
        # Create api_keys table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_keys (
                key_id TEXT PRIMARY KEY,
                api_key TEXT NOT NULL,
                username TEXT NOT NULL,
                created_at TEXT NOT NULL,
                request_count INTEGER DEFAULT 0,
                FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
            )
        ''')
        
        # Seed default users
        default_users = [
            ("admin", "admin", "admin", None),
            ("analyst", "analyst", "analyst", None),
            ("operator", "operator", "operator", None),
            ("auditor", "auditor", "auditor", None),
            ("dev_admin", "dev_admin", "developer", None)
        ]
        
        for username, password, role, oauth in default_users:
            cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
            if not cursor.fetchone():
                cursor.execute(
                    "INSERT INTO users (username, password, role, oauth_provider, created_at) VALUES (?, ?, ?, ?, ?)",
                    (username, password, role, oauth, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                )
                
        conn.commit()
        conn.close()
        print("[Database Manager] SQLite database initialized and seeded successfully.")
    except Exception as e:
        sys.stderr.write(f"[ERROR] Failed to initialize SQLite database: {e}\n")

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
        self.send_header('Content-Security-Policy', "default-src 'self' https://cdn.jsdelivr.net; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; frame-ancestors *;")
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
        elif self.path == '/api/auth/signup':
            self.handle_signup()
        elif self.path == '/api/auth/login':
            self.handle_login()
        elif self.path == '/api/auth/oauth':
            self.handle_oauth()
        elif self.path == '/api/developer/users':
            self.handle_dev_get_users()
        elif self.path == '/api/developer/update-role':
            self.handle_dev_update_role()
        elif self.path == '/api/developer/delete-user':
            self.handle_dev_delete_user()
        elif self.path == '/api/developer/keys':
            self.handle_dev_get_keys()
        elif self.path == '/api/developer/generate-key':
            self.handle_dev_generate_key()
        elif self.path == '/api/developer/delete-key':
            self.handle_dev_delete_key()
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
                rows = excel_validator.parse_csv(file_bytes.decode('utf-8-sig', errors='ignore'))
                
            if not rows or len(rows) < 2:
                self.send_json_response({
                    "success": False,
                    "message": "Incompatible empty or corrupted file template."
                })
                return
                
            headers = rows[0]
            data_rows = rows[1:]
            
            report = excel_validator.validate_sheet_data(headers, data_rows, filename)
            
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

    def handle_signup(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            req_json = json.loads(post_data.decode('utf-8'))
            
            username = req_json.get('username', '').strip()
            password = req_json.get('password', '')
            role = req_json.get('role', 'operator')
            
            if not username or not password:
                self.send_json_response({"success": False, "message": "Username and password required."}, 400)
                return
                
            conn = get_db_conn()
            cursor = conn.cursor()
            
            cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                conn.close()
                self.send_json_response({"success": False, "message": "Username already exists."}, 400)
                return
                
            cursor.execute(
                "INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)",
                (username, password, role, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            )
            conn.commit()
            conn.close()
            
            self.send_json_response({"success": True, "message": "User registered successfully!"})
            
        except Exception as e:
            self.send_json_response({"success": False, "message": f"Signup error: {str(e)}"}, 500)

    def handle_login(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            req_json = json.loads(post_data.decode('utf-8'))
            
            username = req_json.get('username', '').strip()
            password = req_json.get('password', '')
            
            conn = get_db_conn()
            cursor = conn.cursor()
            
            cursor.execute("SELECT username, password, role FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            conn.close()
            
            if not user or user[1] != password:
                self.send_json_response({"success": False, "message": "Invalid username or passcode."}, 401)
                return
                
            self.send_json_response({
                "success": True,
                "username": user[0],
                "role": user[2]
            })
            
        except Exception as e:
            self.send_json_response({"success": False, "message": f"Login error: {str(e)}"}, 500)

    def handle_oauth(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            req_json = json.loads(post_data.decode('utf-8'))
            
            username = req_json.get('username', '').strip()
            provider = req_json.get('provider', 'google')
            
            if not username:
                self.send_json_response({"success": False, "message": "OAuth username required."}, 400)
                return
                
            conn = get_db_conn()
            cursor = conn.cursor()
            
            cursor.execute("SELECT username, role FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            
            if not user:
                # Create user with role analyst by default
                cursor.execute(
                    "INSERT INTO users (username, password, role, oauth_provider, created_at) VALUES (?, ?, ?, ?, ?)",
                    (username, "oauth_derived_secret", "analyst", provider, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                )
                conn.commit()
                role = "analyst"
            else:
                role = user[1]
                
            conn.close()
            
            self.send_json_response({
                "success": True,
                "username": username,
                "role": role,
                "oauth": True
            })
            
        except Exception as e:
            self.send_json_response({"success": False, "message": f"OAuth error: {str(e)}"}, 500)

    def handle_dev_get_users(self):
        try:
            conn = get_db_conn()
            cursor = conn.cursor()
            cursor.execute("SELECT username, role, oauth_provider, created_at FROM users")
            users = cursor.fetchall()
            conn.close()
            
            user_list = []
            for u in users:
                user_list.append({
                    "username": u[0],
                    "role": u[1],
                    "oauth_provider": u[2] or "LDAP/Standard",
                    "created_at": u[3]
                })
                
            self.send_json_response({"success": True, "users": user_list})
        except Exception as e:
            self.send_json_response({"success": False, "message": str(e)}, 500)

    def handle_dev_update_role(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            req_json = json.loads(post_data.decode('utf-8'))
            
            username = req_json.get('username', '')
            role = req_json.get('role', '')
            
            conn = get_db_conn()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET role = ? WHERE username = ?", (role, username))
            conn.commit()
            conn.close()
            
            self.send_json_response({"success": True, "message": "User role updated successfully!"})
        except Exception as e:
            self.send_json_response({"success": False, "message": str(e)}, 500)

    def handle_dev_delete_user(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            req_json = json.loads(post_data.decode('utf-8'))
            
            username = req_json.get('username', '')
            
            if username == "admin":
                self.send_json_response({"success": False, "message": "Cannot delete root admin user."}, 400)
                return
                
            conn = get_db_conn()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users WHERE username = ?", (username,))
            conn.commit()
            conn.close()
            
            self.send_json_response({"success": True, "message": "User deleted successfully!"})
        except Exception as e:
            self.send_json_response({"success": False, "message": str(e)}, 500)

    def handle_dev_get_keys(self):
        try:
            conn = get_db_conn()
            cursor = conn.cursor()
            cursor.execute("SELECT key_id, api_key, username, created_at, request_count FROM api_keys")
            keys = cursor.fetchall()
            conn.close()
            
            key_list = []
            for k in keys:
                key_list.append({
                    "key_id": k[0],
                    "api_key": k[1],
                    "username": k[2],
                    "created_at": k[3],
                    "request_count": k[4]
                })
                
            self.send_json_response({"success": True, "keys": key_list})
        except Exception as e:
            self.send_json_response({"success": False, "message": str(e)}, 500)

    def handle_dev_generate_key(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            req_json = json.loads(post_data.decode('utf-8'))
            
            username = req_json.get('username', '')
            
            token = secrets.token_hex(16)
            api_key = f"amns_sk_{token}"
            key_id = f"id_{token[:8]}"
            
            conn = get_db_conn()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO api_keys (key_id, api_key, username, created_at, request_count) VALUES (?, ?, ?, ?, 0)",
                (key_id, api_key, username, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            )
            conn.commit()
            conn.close()
            
            self.send_json_response({"success": True, "key": {"key_id": key_id, "api_key": api_key, "username": username}})
        except Exception as e:
            self.send_json_response({"success": False, "message": str(e)}, 500)

    def handle_dev_delete_key(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            req_json = json.loads(post_data.decode('utf-8'))
            
            key_id = req_json.get('key_id', '')
            
            conn = get_db_conn()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM api_keys WHERE key_id = ?", (key_id,))
            conn.commit()
            conn.close()
            
            self.send_json_response({"success": True, "message": "API Key revoked successfully!"})
        except Exception as e:
            self.send_json_response({"success": False, "message": str(e)}, 500)


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
    init_db()
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
