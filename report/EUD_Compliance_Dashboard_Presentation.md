---
marp: true
theme: gaia
_class: lead
paginate: true
backgroundColor: #ffffff
color: #0f172a
style: |
  section {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
    padding: 50px;
    font-size: 20px;
  }
  h1 {
    color: #b91c1c;
    font-size: 1.6em;
    border-bottom: 2px solid #0f172a;
    padding-bottom: 10px;
    margin-top: 0;
  }
  h2 {
    color: #334155;
    font-size: 1.2em;
    margin-top: 10px;
  }
  footer {
    font-size: 0.55em;
    color: #64748b;
  }
  header {
    font-size: 0.55em;
    color: #b91c1c;
    font-weight: bold;
    text-transform: uppercase;
  }
  .highlight {
    color: #b91c1c;
    font-weight: bold;
  }
  .caption {
    font-size: 0.7em;
    color: #64748b;
    font-style: italic;
  }
  table {
    font-size: 0.75em;
    width: 100%;
    border-collapse: collapse;
  }
  th {
    background-color: #f1f5f9;
    color: #0f172a;
    font-weight: bold;
    border-bottom: 2px solid #cbd5e1;
  }
  td, th {
    padding: 8px 12px;
    border-bottom: 1px solid #cbd5e1;
  }
---

# Thrawn EUD.
## Security & Ingest Portal Gateway: Executive Console & Asset Ledger
### Technical Architecture & Walkthrough

---

# Executive Summary
## Bridging the Compliance Gap
- **Problem:** Enterprise networks suffer from telemetry blindspots. Traditional inventories fail to reconcile directory databases with real-time agent presence.
- **Solution:** The **EUD Compliance Dashboard** provides unified posture visibility:
  - **Aggregated Telemetry:** Integrates AD, EDR (SentinelOne), MDM, VPN (Zscaler), and vulnerability scanners (Nessus).
  - **Instant Verification:** Evaluates endpoint coverage against strict security frameworks.
  - **Rogue Discovery:** Unmasks unmanaged devices immediately upon sheet ingestion.

---

# Technical Architecture
## Decentralized Client-Side Architecture
- **Presentation Layer:** Built with HTML5, CSS3, and Vanilla JavaScript. Zero runtime or daemon dependencies, ensuring instant rendering.
- **Scoring Engine:** Evaluates controls client-side based on custom governance policies.
- **Reconciliation Workspace:** O(N) map-based merge engine processes large datasets.
- **DOM Virtualization:** Renders tabular device ledgers in paginated fragments to ensure butter-smooth user interactions (10k+ entries).

---

# Core Engine: Zero-Tolerance Score
## Binary Compliance Model
- **Zero-Tolerance Principle:** If a single mandated control evaluates as `MISSING` or `NON_COMPLIANT`, the device's score drops to <span class="highlight">0.00</span> and its state becomes `NON_COMPLIANT`.
- **Governance Controls:**
  - **Optional Toggles:** The board can toggle control requirements to "Optional," dynamically bypassing compliance checks.
  - **OS-Family Applicability:** Bypasses Windows-specific controls (`ad`, `bitlocker`, `sccm`) on macOS/Linux endpoints to prevent false alerts.

---

# The Reconciliation Pipeline
## Multi-Stage Identity Alignment
- **Stage 1: Normalization Match**
  - Hostnames normalized via regex: `replace(/[^a-zA-Z0-9]/g, "")` for $100\%$ character parity.
- **Stage 2: Cryptographic Match**
  - Generates SHA-256 signatures from hardware serials, MAC addresses, and manufacturer profiles.
- **Stage 3: Edit-Distance Alignment**
  - Calculates Levenshtein edit distance to match slightly drifted device records.

---

# Algorithmic Optimization
## O(N) Map-Based Bulk Ingest Merging
- **O(1) Pre-Indexed Maps:** Replaced nested search loops $O(N^2)$ with lookups indexed by Name, Serial, and MAC.
- **Performance Breakthrough:** Merges **10,029 devices** in <span class="highlight">under 50 milliseconds</span> (previously took 30–60 seconds of browser thread lockups).
- **Batched Reflows:** Utilizes `DocumentFragment` instances to perform off-DOM list assembly, eliminating screen flickering.

---

# Mandated Policies (6 Core Controls)

| Policy | Target OS | Key | Description |
| :--- | :--- | :--- | :--- |
| **AD Enrollment** | Windows | `ad` | Verifies domain enrollment status |
| **BitLocker** | Windows | `bitlocker` | Validates volume storage encryption |
| **Zscaler** | All | `zscaler` | Confirms cloud proxy/VPN agent check-in |
| **Nessus** | All | `nessus` | Validates active vulnerability scanning |
| **SentinelOne** | All | `sentinelone` | Confirms active EDR coverage |
| **SCCM Agent** | Windows | `sccm` | Confirms patch management check-in |

---

# Security Principles & Hardening
## Safeguarding GRC Telemetry
- **Stored XSS Prevention:** HTML entity sanitization on all user input/imported properties via custom `escapeHTML` encoder.
- **CSV Formula Injection Mitigation:** Sanitizes cells starting with control characters (`=`, `+`, `-`, `@`, `\t`, `\r`) in dynamic CSV exports by prefixing them with a single quote.
- **Role-Based Access Control (RBAC):** Restricts dangerous API endpoints (network isolation, settings override, databases merge) according to roles (Admin, Analyst, Operator, Auditor).

---

# Ingestion & Operation Workflow
## Step-by-Step Operator Flow
1. **Access Gateway:** Authenticate using LDAP credentials and vault PIN via the portal.
2. **Ingest Sheets:** Select telemetry CSV/Excel sheets in the Reconciliation Workspace.
3. **Align Schema:** Map file headers to canonical device attributes.
4. **Audit Gaps:** Inspect mismatched records (coverage gaps and rogue devices).
5. **Merge to Ledger:** Commit changes to the active compliant fleet ledger.

---

# Future Roadmap
## System Evolution Plan
- **Live Integrations:** Move from manual file uploads to direct webhooks and API hooks with CrowdStrike, Azure AD, and Microsoft Sentinel.
- **ML Anomaly Detection:** Implement local isolation forest algorithms to flag suspicious location shifts and unusual logins.
- **Self-Healing Loop:** Automatically trigger remediation shell scripts (e.g. force BitLocker key escrow or deploy Nessus agents) when a device score falls to `0.00`.
- **Blockchain Compliance Logs:** Log GRC audits to a cryptographically validated write-once-read-many database.
