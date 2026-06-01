# 🛡️ EUD Compliance Dashboard

[![Go Version](https://img.shields.io/badge/Go-1.22-00ADD8?style=flat-square&logo=go&logoColor=white)](https://golang.org)
[![Database](https://img.shields.io/badge/Database-PostgreSQL%20%26%20Timescale-4169E1?style=flat-square&logo=postgresql&logoColor=white)](https://timescale.com)

A premium, enterprise-grade **End-User Device (EUD) Compliance & Risk Management Platform**. It aggregates security logs, evaluates endpoint controls against strict operational frameworks (EDR, Zero Trust, Patching), calculates normalized device risk scores using an advanced penalty-based risk engine, and resolves device identities through multi-stage cryptographic and edit-distance reconciliation.

---

## 🏛️ System Architecture

The platform is designed as a modular, multi-layered system:

```mermaid
graph TD
    subgraph Frontend [Presentation Layer]
        UI[Compliance Dashboard HTML/CSS/JS]
        RBAC[Role-Based Privilege Gate]
    end

    subgraph Backend [Core Compliance Engine]
        Collector[CSV & API Log Collector]
        Evaluator[Multi-Dimension Control Evaluator]
        RiskEngine[Penalty-Based Risk Scoring Engine]
        DB[(PostgreSQL & TimescaleDB)]
    end

    subgraph Reconciler [Reconciliation Workspace]
        Matcher[Exact / Fingerprint / Levenshtein Reconciler]
    end

    UI -->|Role Authorization| RBAC
    Collector -->|Raw Logs| Evaluator
    Evaluator -->|Dimension Scoring| RiskEngine
    RiskEngine -->|Timeseries Logs| DB
    Collector -->|Ingest Assets| Matcher
    Matcher -->|Auto-Merge / Queue Action| UI
```

---

## 🌟 Key Features

### 1. 🖥️ Premium Frontend Dashboard
*   **Aesthetics**: Harmonious high-contrast dark mode tailored for Security Operations Centers (SOCs).
*   **Security Actions**: Context-isolated network mitigation controls (e.g. isolate compromised devices, trigger immediate hotfix patch deploys, force re-enrollment).
*   **Granular RBAC**: strict interface gating for four customized operational personas:
    *   **Administrator**: Full administrative & mutation capabilities.
    *   **Security Analyst**: Incident inspection, risk scoring overrides, threat tracking.
    *   **System Operator**: Safe deployment execution, telemetry collection.
    *   **External Compliance Auditor**: Restricted Read-Only ledger access.

### 2. ⚙️ Go-Based Core Compliance Engine (`/backend`)
*   **Multi-Dimension Evaluator**: Evaluates device endpoints on six critical modern vectors:
    *   `EDR` (Endpoint Detection & Response protection status)
    *   `PATCH` (OS and security updates currency)
    *   `VULNERABILITY` (Active CVE exposures)
    *   `ENCRYPTION` (BitLocker / FileVault storage locks)
    *   `NETWORK` (Zero Trust network isolation & VPN)
    *   `IDENTITY` (MFA, Active Directory status)
*   **Dynamic Multi-Parameter Ingestion**: Automatically detects compliance and security columns from any imported Excel/CSV spreadsheet (using fuzzy-matching and presence validations), appending them dynamically to the device's monitored controls in the ledger and selection widgets.
*   **Composite Compliance Engine**:
    *   Computes normalized compliance scores ($0.00$ or $100.00$).
    *   Applies a **Zero-Tolerance Binary Compliance Model**: If even a single core or dynamic control agent evaluates as non-compliant/missing, the entire asset's score instantly drops to `0.00` and its state is set to `NON_COMPLIANT`.

### 3. 🛡️ Cryptographic & Edit-Distance Reconciler
*   **Cryptographic Hardware Fingerprinting**: Calculates deterministic SHA-256 signatures from serials, MAC addresses, and manufacturer profiles to uniquely identify physical endpoints.
*   **Levenshtein Edit-Distance Comparison**: Performs programmatic string distance matching to compare incoming host telemetries with active directory records, automatically aligning close matches (e.g. `DESKTOP-A1B2` vs `desktop-a1b2-corp`) within high-fidelity threshold parameters.
*   **Multi-Stage Alignment Pipelines**:
    *   **Stage 1: Exact Match**: Automated name matching (100% confidence).
    *   **Stage 2: Cryptographic Match**: Hardware fingerprint matching (95% confidence).
    *   **Stage 3: Edit-Distance Match**: Dynamic Levenshtein alignments (calculated trust boundaries).
    *   **Stage 5: Review Queue**: Programmatically routes untrusted records to the manual verification queue.

### 4. 🗄️ Timeseries Database Schemas (`/schemas`)
*   Optimized PostgreSQL schema blueprints.
*   TimescaleDB hypertable setups built to handle high-frequency timeseries state logs, tracking device compliance state histories efficiently over multi-year scales.

---

## 📂 Project Structure

```
.
├── backend/
│   ├── go.mod                 # Go module definition
│   └── pkg/
│       ├── collector/         # CSV / API data collectors
│       ├── evaluator/         # Multi-dimension compliance evaluation & risk engine
│       ├── integration/       # Alert dispatchers & webhooks
│       └── tenant/            # Tenant isolation and context management
├── frontend/
│   ├── index.html             # High-fidelity dashboard application
│   └── style.css              # Custom dark-theme stylesheet
├── schemas/
│   ├── postgres/              # Relational core table schemas
│   └── timescale/             # Hypertable definitions for compliance history log
└── .gitignore                 # Safe, comprehensive exclude list
```

---

## 🚀 Setup & Execution Guide

### 1. Frontend
Simply load the high-fidelity index inside any modern browser:
```bash
# Double-click or serve using a static server
cd frontend
npx browser-sync start --server --files "*.html, *.css"
```

### 2. Backend (Go)
Navigate to `/backend` and compile or test the core evaluation packages:
```bash
cd backend
# Run core evaluator & risk engine tests
go test ./pkg/evaluator/...
```

---

## 🛡️ Binary Compliance Model

The platform enforces a zero-tolerance, high-fidelity binary status framework to maximize fleet security:

| Compliance State | Score | Description | Operational Response |
| :--- | :--- | :--- | :--- |
| 🟢 **COMPLIANT** | **100.00** | All core and custom dynamic controls are active and verified. | Normal operations, continuous background telemetry collection. |
| 🔴 **NON_COMPLIANT** | **0.00** | One or more control agents are missing, disabled, or isolated. | **Zero-Trust Network Containment Triggered**: Immediate routes block, automated remote patch deployment initiated. |

---

## 🏛️ Policy Governance & Simplified Reporting

To deliver streamlined SOC operations, the platform implements a tight feedback loop between active policies and executive report telemetry:

### 1. 🛡️ Security Policies Governance Board
*   **Dynamic Policies Registry**: scans both core enterprise policies and any custom columns imported from uploaded spreadsheets to register them as active fleet controls dynamically.
*   **Enforcement Toggles (Required vs Optional)**: Administrators can globally toggle a control's verification mandate. Optional controls are excluded from zero-compliance penalty calculations.
*   **Instant Recalculation**: Toggling a policy's status automatically recalculates scores across the entire fleet grid ledger, metric widgets, pie/donut charts, and reporting audits in real-time.
*   **RBAC Protected**: Modification of global policy constraints is strictly gated to the Global Security Administrator (`admin.security`). Other operators/auditors are restricted to read-only views.

### 2. 📊 Compliance Telemetry Reporting Center
*   **Real-time Fleet Audits**: Summarizes aggregate managed endpoint counts, perfect compliance rates, and exception metrics dynamically across whatever dataset has been loaded.
*   **Control Performance Audits**: Audits pass/fail statistics, pass rate percentage, and displays visual compliance verification progress bars for every loaded mandate.
*   **Click-to-Remediate Redirection**: Identifies the top 10 systems violating active mandates and lists their exact control gaps. Clicking the `Remediate` link immediately switches the dashboard view to the Compliance Ledger, auto-selects the endpoint, and focuses the detailed MECM/EDR remediation tools panel.

### 3. 📥 Real-time Spreadsheet Ingestion & Export
*   **Fuzzy Header Mapping**: Smart index mapping rules identify device names, serials, macs, locations, and condition keys automatically from imported Excel (`.xlsx`, `.xls`) or CSV sheets.
*   **Dynamic Custom Columns Parsing**: Instantly detects and classifies miscellaneous columns (e.g. `mfa_status`, `agent_v3_active`) as dynamic compliance controls, automatically registering them on the **Security Policies Governance Board** and parsing them in the zero-tolerance engine.
*   **Pristine CSV Export**: Compiles and downloads the current active filtered fleet ledger matching all active queries, searches, and status parameters cleanly.

---

## 🔄 Multi-Sheet Asset Reconciliation Workspace

To support large-scale asset tracking and multi-agent compliance audits, the platform features a highly sophisticated **Multi-Sheet Asset Reconciliation Workspace**:

### 1. ⚡ Cross-Sheet Multi-Agent Alignment
*   **Multi-Ingestion Queue**: Bulk upload multiple CSV/Excel spreadsheets representing different directories or agent check-ins (e.g. Active Directory, EDR SentinelOne logs, SCCM records).
*   **Fuzzy Key Matching**: Set role classifications (Primary Corporate Directory vs. Secondary Agent Telemetries) and customize device/hostname alignment keys for each sheet dynamically.
*   **Automated Verification Pipeline**:
    *   **Reconciled Matches**: Devices correctly aligned across all primary and secondary telemetries.
    *   **Coverage Gaps (Non-Compliant)**: Assets registered in the Corporate Directory but missing checking records in one or more agent telemetries. Drops compliance score to `0.00` immediately.
    *   **Rogue Assets (Unmanaged)**: Untracked endpoints discovered checking in to agent telemetries but missing from the Corporate Directory.
*   **Asset Ingest Merge**: Merge verified alignment parameters and dynamic Excel custom properties directly into the live dashboard fleet database instantly.

### 2. ⚡ High-Performance DOM Virtualization (UI Freeze Fix)
*   To seamlessly render large reconciliation sets (e.g. **16,742 records**) without freezing the browser UI or triggering "page isn't responding" errors, the reconciliation table uses a virtualized paginated controller (`reconPageSize = 10` by default).
*   DOM updates inside `renderReconTableBody()` are batched in memory using high-efficiency `DocumentFragment` templates (with graceful fallback for testing context) before appending to the live DOM tree, keeping layout calculations instant and the browser thread perfectly responsive.

### 3. 📊 Tabular Flat CSV Reporting Matrix
*   **Flat Matrix Export**: Instead of cramming all dynamic properties into a single text column, the refactored reconciliation CSV exporter compiles a structured flat spreadsheet matrix containing distinct headers for every unique sheet property (`[filename.csv] PropertyName`).
*   **Scalable Blob Stream Downloads**: Large export streams are compiled into UTF-8 encoded binary `Blob` objects and served via local memory references (`URL.createObjectURL`), bypassing standard URI string constraints and securing flawless downloads of tens of thousands of rows.


