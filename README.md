# Compliance & Reconciliation Dashboard

A premium **Compliance & Reconciliation Dashboard** for End-User Devices (EUD). It aggregates asset checklists, runs automated security audits, and reconciles multi-sheet inventory databases with zero external Python dependencies.

## Key Features

* **Ledger View:** Displays compliance status across all devices.
* **Asset Reconciler:** Merges multi-sheet spreadsheet directory data to find inventory matches, coverage gaps, and rogue assets.
* **Automated Security Audits:** Evaluates HTTP headers (HSTS, secure flags, CSP) and local agent health against the 6 core policies:
  * Active Directory
  * BitLocker
  * Zscaler
  * Nessus
  * SentinelOne
  * SCCM
* **Data Portability:** Exports compliance data and reports to PDF, HTML, and JSON formats.

## Project Structure

```
.
├── backend/
│   └── app/
│       ├── main.py            # FastAPI Application bootstrap
│       ├── database.py        # SQLAlchemy SQLite engine configuration
│       ├── security.py        # SSRF checks, URL validation, and cryptographic hash verification
│       ├── assessment/        # Assessment/Findings database schemas, services & routers
│       ├── checklist/         # YAML checklist loaders and policy evaluation interpreters
│       ├── evidence/          # Immutable evidence store & SHA-256 validation endpoints
│       └── reports/           # HTML and PDF compliance report generators
├── frontend/
│   ├── index.html             # Single-page compliance console
│   ├── style.css              # Custom minimalist stylesheet
│   └── favicon.png            # Tab icon
└── tests/                     # Automated JS and Python test suite scripts
```

## Running Locally

Ensure Python 3.10+ is installed. Start the FastAPI server using Uvicorn:

```bash
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8080
```
Open browser at: `http://127.0.0.1:8080/index.html`.

## Running Verification Tests

Run the automated test suites to verify backend endpoints, spreadsheet reconciliation, and frontend logic:

```bash
# Run backend Python tests
python -m unittest tests/test_api.py tests/test_mapping_engine.py tests/test_security.py

# Run frontend JavaScript tests
node tests/test-syntax.js
node tests/test-runtime.js
node tests/test-interaction.js
node tests/test-telemetry-leakage.js
node tests/test-distinct-merge-keys.js
node tests/verify-details-table.js
node tests/verify-reporting-policies.js
node tests/verify-ad-windows-only.js
node tests/test-mismatched-keys-prevention.js
node tests/test-rogue-actions.js
```
