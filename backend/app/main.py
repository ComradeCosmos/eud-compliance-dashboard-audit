import os
import sys
import base64
import sqlite3
import secrets
from datetime import datetime
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Depends, HTTPException, Body
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

# Add the project root to sys.path so we can import excel_validator and backend modules
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

import excel_validator
from backend.app.database import engine, Base, get_db, SessionLocal
from backend.app.evidence.router import router as evidence_router
from backend.app.assessment.router import router as assessment_router
from backend.app.checklist.router import router as checklist_router
from backend.app.risk.router import router as risk_router
from backend.app.siem.router import router as siem_router
from backend.app.reports.router import router as reports_router
from backend.app.scanners.router import router as scanners_router

# Initialize FastAPI app
app = FastAPI(
    title="SAMP API & Dashboard Gateway",
    description="Integrated SIEM Event Ingestion Pipeline, Risk Engine & Security Audit Management Platform",
    version="1.0.0"
)

# Enable CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Startup event to create database tables
@app.on_event("startup")
def on_startup():
    # Create tables for new SAMP backend (evidence, assessments, findings)
    Base.metadata.create_all(bind=engine)
    
    # Initialize the original users SQLite database
    init_original_db()

    # Seed default assessment session if database is empty
    try:
        db = SessionLocal()
        from backend.app.assessment.models import Assessment
        if db.query(Assessment).count() == 0:
            default_audit = Assessment(
                name="AM/NS Enterprise Audit 2026",
                environment="Production",
                status="IN_PROGRESS"
            )
            db.add(default_audit)
            db.commit()
            print("[Database Manager] Default assessment session seeded successfully.")
        db.close()
    except Exception as e:
        print(f"[Database Manager] Failed to seed default assessment: {e}")

# Include all module routers
app.include_router(evidence_router)
app.include_router(assessment_router)
app.include_router(checklist_router)
app.include_router(risk_router)
app.include_router(siem_router)
app.include_router(reports_router)
app.include_router(scanners_router)


# ----------------------------------------------------
# Original DB Initialization and seeding (database.db)
# ----------------------------------------------------
def get_original_db_conn():
    db_path = os.path.join(PROJECT_ROOT, 'database.db')
    return sqlite3.connect(db_path)

def init_original_db():
    try:
        conn = get_original_db_conn()
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
        print("[Database Manager] Original SQLite database initialized and seeded successfully.")
    except Exception as e:
        sys.stderr.write(f"[ERROR] Failed to initialize original SQLite database: {e}\n")


# ----------------------------------------------------
# Re-implementation of original backend endpoints
# ----------------------------------------------------

@app.post("/api/validate-sheet")
def validate_sheet(payload: dict = Body(...)):
    try:
        filename = payload.get('filename', '')
        base64_content = payload.get('content', '')
        
        file_bytes = base64.b64decode(base64_content)
        
        if filename.lower().endswith('.xlsx'):
            rows = excel_validator.parse_xlsx(file_bytes)
        else:
            rows = excel_validator.parse_csv(file_bytes.decode('utf-8-sig', errors='ignore'))
            
        if not rows or len(rows) < 2:
            return {"success": False, "message": "Incompatible empty or corrupted file template."}
            
        headers = rows[0]
        data_rows = rows[1:]
        
        report = excel_validator.validate_sheet_data(headers, data_rows, filename)
        
        return {
            "success": True,
            "filename": filename,
            "headers": headers,
            "rows": rows,
            "validation_report": report
        }
    except Exception as e:
        return {"success": False, "message": f"Server-side parsing failed: {str(e)}"}

@app.post("/api/reconcile-sheets")
def reconcile_sheets(payload: dict = Body(...)):
    try:
        sheets = payload.get('sheets', [])
        if len(sheets) < 2:
            return {"success": False, "message": "Reconciliation requires at least two sheets."}
            
        primary_sheet = None
        secondary_sheets = []
        for sheet in sheets:
            if sheet.get('role') == 'primary':
                primary_sheet = sheet
            else:
                secondary_sheets.append(sheet)
                
        if not primary_sheet or not secondary_sheets:
            return {"success": False, "message": "Deep reconciliation requires 1 Primary and at least 1 Secondary sheet."}
            
        results = excel_validator.reconcile_sheets_data(primary_sheet, secondary_sheets)
        return {"success": True, "results": results}
    except Exception as e:
        return {"success": False, "message": f"Server-side reconciliation failed: {str(e)}"}

@app.post("/api/auth/signup")
def signup(payload: dict = Body(...)):
    try:
        username = payload.get('username', '').strip()
        password = payload.get('password', '')
        role = payload.get('role', 'operator')
        
        if not username or not password:
            raise HTTPException(status_code=400, detail="Username and password required.")
            
        conn = get_original_db_conn()
        cursor = conn.cursor()
        
        cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            conn.close()
            raise HTTPException(status_code=400, detail="Username already exists.")
            
        cursor.execute(
            "INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)",
            (username, password, role, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        )
        conn.commit()
        conn.close()
        return {"success": True, "message": "User registered successfully!"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Signup error: {str(e)}")

@app.post("/api/auth/login")
def login(payload: dict = Body(...)):
    try:
        username = payload.get('username', '').strip()
        password = payload.get('password', '')
        
        conn = get_original_db_conn()
        cursor = conn.cursor()
        
        cursor.execute("SELECT username, password, role FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        if not user or user[1] != password:
            raise HTTPException(status_code=401, detail="Invalid username or passcode.")
            
        return {
            "success": True,
            "username": user[0],
            "role": user[2]
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Login error: {str(e)}")

@app.post("/api/auth/oauth")
def oauth(payload: dict = Body(...)):
    try:
        username = payload.get('username', '').strip()
        provider = payload.get('provider', 'google')
        
        if not username:
            raise HTTPException(status_code=400, detail="OAuth username required.")
            
        conn = get_original_db_conn()
        cursor = conn.cursor()
        
        cursor.execute("SELECT username, role FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if not user:
            cursor.execute(
                "INSERT INTO users (username, password, role, oauth_provider, created_at) VALUES (?, ?, ?, ?, ?)",
                (username, "oauth_derived_secret", "analyst", provider, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            )
            conn.commit()
            role = "analyst"
        else:
            role = user[1]
            
        conn.close()
        return {
            "success": True,
            "username": username,
            "role": role,
            "oauth": True
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OAuth error: {str(e)}")

@app.post("/api/developer/users")
def dev_get_users():
    try:
        conn = get_original_db_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT username, role, oauth_provider, created_at FROM users")
        users = cursor.fetchall()
        conn.close()
        
        user_list = [
            {
                "username": u[0],
                "role": u[1],
                "oauth_provider": u[2] or "LDAP/Standard",
                "created_at": u[3]
            } for u in users
        ]
        return {"success": True, "users": user_list}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/developer/update-role")
def dev_update_role(payload: dict = Body(...)):
    try:
        username = payload.get('username', '')
        role = payload.get('role', '')
        
        conn = get_original_db_conn()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET role = ? WHERE username = ?", (role, username))
        conn.commit()
        conn.close()
        return {"success": True, "message": "User role updated successfully!"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/developer/delete-user")
def dev_delete_user(payload: dict = Body(...)):
    try:
        username = payload.get('username', '')
        if username == "admin":
            raise HTTPException(status_code=400, detail="Cannot delete root admin user.")
            
        conn = get_original_db_conn()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
        conn.close()
        return {"success": True, "message": "User deleted successfully!"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/developer/keys")
def dev_get_keys():
    try:
        conn = get_original_db_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT key_id, api_key, username, created_at, request_count FROM api_keys")
        keys = cursor.fetchall()
        conn.close()
        
        key_list = [
            {
                "key_id": k[0],
                "api_key": k[1],
                "username": k[2],
                "created_at": k[3],
                "request_count": k[4]
            } for k in keys
        ]
        return {"success": True, "keys": key_list}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/developer/generate-key")
def dev_generate_key(payload: dict = Body(...)):
    try:
        username = payload.get('username', '')
        token = secrets.token_hex(16)
        api_key = f"amns_sk_{token}"
        key_id = f"id_{token[:8]}"
        
        conn = get_original_db_conn()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO api_keys (key_id, api_key, username, created_at, request_count) VALUES (?, ?, ?, ?, 0)",
            (key_id, api_key, username, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        )
        conn.commit()
        conn.close()
        return {"success": True, "key": {"key_id": key_id, "api_key": api_key, "username": username}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/developer/delete-key")
def dev_delete_key(payload: dict = Body(...)):
    try:
        key_id = payload.get('key_id', '')
        
        conn = get_original_db_conn()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM api_keys WHERE key_id = ?", (key_id,))
        conn.commit()
        conn.close()
        return {"success": True, "message": "API Key revoked successfully!"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ----------------------------------------------------
# Static Files & SPA Routing
# ----------------------------------------------------
frontend_dir = os.path.join(PROJECT_ROOT, "frontend")

@app.get("/")
def read_root():
    index_path = os.path.join(frontend_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "Frontend index.html not found"}

@app.get("/{path:path}")
def read_static(path: str):
    # Prevent directory traversal attacks
    resolved_path = os.path.abspath(os.path.join(frontend_dir, path))
    if not resolved_path.startswith(os.path.abspath(frontend_dir)):
        index_path = os.path.join(frontend_dir, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)
        return {"message": "Access Denied: Path Traversal Blocked"}
        
    if os.path.exists(resolved_path) and not os.path.isdir(resolved_path):
        return FileResponse(resolved_path)
    # Default fallback to index.html for SPA router routing
    index_path = os.path.join(frontend_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "Frontend index.html not found"}
