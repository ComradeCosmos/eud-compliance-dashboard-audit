import io
from datetime import datetime
from sqlalchemy.orm import Session
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

from backend.app.assessment import services as assessment_services
from backend.app.evidence import services as evidence_services
from backend.app.checklist import services as checklist_services

def generate_json_report(db: Session, assessment_id: int) -> dict:
    """Generates a complete JSON format compliance audit report."""
    assessment = assessment_services.get_assessment(db, assessment_id)
    if not assessment:
        raise ValueError(f"Assessment {assessment_id} not found")
        
    findings = assessment_services.list_findings(db, assessment_id)
    evidence_list = evidence_services.list_evidence(db, assessment_id)
    
    # Verify overall evidence integrity
    evidence_verified = evidence_services.verify_all_evidence_for_assessment(db, assessment_id)
    
    return {
        "assessment_id": assessment.id,
        "name": assessment.name,
        "environment": assessment.environment,
        "status": assessment.status,
        "overall_score": assessment.overall_score,
        "created_at": assessment.created_at.isoformat(),
        "evidence_integrity_verified": evidence_verified,
        "findings": [
            {
                "control_code": f.control_code,
                "control_title": f.control_title,
                "severity": f.severity,
                "status": f.status,
                "details": f.details,
                "recommendation": f.recommendation,
                "type": f.type,
                "checked_at": f.checked_at.isoformat()
            } for f in findings
        ],
        "evidence": [
            {
                "id": ev.id,
                "source": ev.source,
                "collected_at": ev.collected_at,
                "hash_signature": ev.hash_signature,
                "is_verified": ev.is_verified
            } for ev in evidence_list
        ]
    }

def generate_html_report(db: Session, assessment_id: int) -> str:
    """Generates a styled HTML dashboard representation of the compliance audit."""
    data = generate_json_report(db, assessment_id)
    
    findings_rows = ""
    for f in data["findings"]:
        status_color = "#10b981" if f["status"] == "PASS" else "#ef4444"
        severity_color = "#3b82f6" if f["severity"] == "LOW" else "#f59e0b" if f["severity"] == "MEDIUM" else "#ef4444"
        findings_rows += f"""
        <tr>
            <td style="font-weight: bold; padding: 12px; border-bottom: 1px solid #e2e8f0;">{f['control_code']}</td>
            <td style="padding: 12px; border-bottom: 1px solid #e2e8f0;">{f['control_title']}</td>
            <td style="padding: 12px; border-bottom: 1px solid #e2e8f0;"><span style="color: {severity_color}; font-weight: bold;">{f['severity']}</span></td>
            <td style="padding: 12px; border-bottom: 1px solid #e2e8f0;"><span style="background-color: {status_color}1a; color: {status_color}; padding: 4px 8px; border-radius: 4px; font-weight: bold;">{f['status']}</span></td>
            <td style="padding: 12px; border-bottom: 1px solid #e2e8f0; font-size: 0.9em; color: #4a5568;">{f['details'] or ''}</td>
            <td style="padding: 12px; border-bottom: 1px solid #e2e8f0; font-size: 0.9em; color: #4a5568;"><i>{f['recommendation'] or ''}</i></td>
        </tr>
        """
        
    evidence_rows = ""
    for ev in data["evidence"]:
        verification_status = "🟢 SECURE" if ev["is_verified"] else "🔴 COMPROMISED"
        evidence_rows += f"""
        <div style="background-color: #f7fafc; padding: 10px; border: 1px solid #e2e8f0; border-radius: 4px; margin-bottom: 8px; font-family: monospace; font-size: 0.85em;">
            <strong>Source:</strong> {ev['source']} | 
            <strong>Collected At:</strong> {ev['collected_at']} | 
            <strong>SHA-256 Hash:</strong> {ev['hash_signature']} | 
            <strong>Integrity:</strong> {verification_status}
        </div>
        """
        
    integrity_color = "#10b981" if data["evidence_integrity_verified"] else "#ef4444"
    integrity_text = "PASS (All Evidence Signatures Valid)" if data["evidence_integrity_verified"] else "FAIL (Evidence Tampering Detected!)"
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>EUD Compliance Report</title>
        <meta charset="utf-8">
    </head>
    <body style="font-family: system-ui, sans-serif; background-color: #f8fafc; color: #1e293b; padding: 40px; margin: 0;">
        <div style="max-width: 1000px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);">
            <div style="border-bottom: 2px solid #ef4444; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h1 style="margin: 0; font-size: 24px; color: #0f172a; text-transform: uppercase;">AM/NS India Security Portal</h1>
                    <p style="margin: 5px 0 0 0; color: #64748b; font-size: 14px; font-weight: bold; text-transform: uppercase; letter-spacing: 0.05em;">End-User Device Compliance Dashboard (EUD)</p>
                </div>
                <div style="text-align: right;">
                    <div style="font-size: 28px; font-weight: 800; color: #ef4444;">{data['overall_score']}%</div>
                    <div style="font-size: 11px; text-transform: uppercase; color: #64748b; font-weight: bold;">Compliance Score</div>
                </div>
            </div>
            
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 30px;">
                <div style="background-color: #f8fafc; padding: 15px; border-radius: 6px; border: 1px solid #e2e8f0;">
                    <span style="font-size: 12px; text-transform: uppercase; color: #64748b; font-weight: bold;">Assessment Name</span>
                    <div style="font-size: 16px; font-weight: bold; margin-top: 5px;">{data['name']}</div>
                </div>
                <div style="background-color: #f8fafc; padding: 15px; border-radius: 6px; border: 1px solid #e2e8f0;">
                    <span style="font-size: 12px; text-transform: uppercase; color: #64748b; font-weight: bold;">Environment</span>
                    <div style="font-size: 16px; font-weight: bold; margin-top: 5px;">{data['environment'].upper()}</div>
                </div>
                <div style="background-color: #f8fafc; padding: 15px; border-radius: 6px; border: 1px solid #e2e8f0;">
                    <span style="font-size: 12px; text-transform: uppercase; color: #64748b; font-weight: bold;">Date Compiled</span>
                    <div style="font-size: 16px; font-weight: bold; margin-top: 5px;">{data['created_at'][:19].replace("T", " ")}</div>
                </div>
            </div>

            <div style="background-color: {integrity_color}1a; border: 1px solid {integrity_color}; border-radius: 6px; padding: 15px; margin-bottom: 30px; font-weight: bold; color: {integrity_color};">
                🔒 Evidence Cryptographic Verification: {integrity_text}
            </div>

            <h3 style="border-bottom: 1px solid #e2e8f0; padding-bottom: 10px; margin-top: 40px; margin-bottom: 20px; text-transform: uppercase; font-size: 16px; letter-spacing: 0.05em;">Evaluated Security Controls (10 Mandates)</h3>
            <table style="width: 100%; border-collapse: collapse; text-align: left;">
                <thead>
                    <tr style="background-color: #f1f5f9;">
                        <th style="padding: 12px; border-bottom: 2px solid #cbd5e1; font-size: 13px; text-transform: uppercase;">Code</th>
                        <th style="padding: 12px; border-bottom: 2px solid #cbd5e1; font-size: 13px; text-transform: uppercase;">Control</th>
                        <th style="padding: 12px; border-bottom: 2px solid #cbd5e1; font-size: 13px; text-transform: uppercase;">Severity</th>
                        <th style="padding: 12px; border-bottom: 2px solid #cbd5e1; font-size: 13px; text-transform: uppercase;">Status</th>
                        <th style="padding: 12px; border-bottom: 2px solid #cbd5e1; font-size: 13px; text-transform: uppercase;">Finding Details</th>
                        <th style="padding: 12px; border-bottom: 2px solid #cbd5e1; font-size: 13px; text-transform: uppercase;">Remediation Recommendation</th>
                    </tr>
                </thead>
                <tbody>
                    {findings_rows}
                </tbody>
            </table>
            
            <h3 style="border-bottom: 1px solid #e2e8f0; padding-bottom: 10px; margin-top: 40px; margin-bottom: 20px; text-transform: uppercase; font-size: 16px; letter-spacing: 0.05em;">Immutable Evidence Signatures</h3>
            <div>
                {evidence_rows}
            </div>
        </div>
    </body>
    </html>
    """
    return html

def generate_pdf_report(db: Session, assessment_id: int) -> bytes:
    """Generates a beautifully styled corporate audit PDF report using ReportLab."""
    data = generate_json_report(db, assessment_id)
    
    # Set up in-memory buffer
    buffer = io.BytesIO()
    
    # Custom document margin
    doc = SimpleDocTemplate(
        buffer, 
        pagesize=letter, 
        rightMargin=36, 
        leftMargin=36, 
        topMargin=36, 
        bottomMargin=36
    )
    
    story = []
    styles = getSampleStyleSheet()
    
    # Custom colors
    primary_color = colors.HexColor("#ef4444")  # AM/NS Crimson Red
    text_dark = colors.HexColor("#0f172a")
    text_muted = colors.HexColor("#475569")
    bg_light = colors.HexColor("#f8fafc")
    
    # Define styles
    title_style = ParagraphStyle(
        'DocTitle', 
        parent=styles['Heading1'], 
        fontName='Helvetica-Bold', 
        fontSize=20, 
        textColor=text_dark, 
        spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        'DocSubTitle', 
        parent=styles['Normal'], 
        fontName='Helvetica-Bold', 
        fontSize=9, 
        textColor=text_muted, 
        spaceAfter=15
    )
    h2_style = ParagraphStyle(
        'SectionHeader', 
        parent=styles['Heading2'], 
        fontName='Helvetica-Bold', 
        fontSize=12, 
        textColor=primary_color, 
        spaceBefore=15, 
        spaceAfter=8, 
        borderPadding=(0,0,1,0),
        borderColor=primary_color
    )
    body_style = ParagraphStyle(
        'Body', 
        parent=styles['Normal'], 
        fontName='Helvetica', 
        fontSize=8.5, 
        textColor=text_dark, 
        leading=11
    )
    mono_style = ParagraphStyle(
        'Mono', 
        parent=styles['Normal'], 
        fontName='Courier', 
        fontSize=7, 
        textColor=text_muted, 
        leading=9
    )
    
    # Header block
    story.append(Paragraph("AM/NS INDIA SECURITY COMPLIANCE REPORT", title_style))
    story.append(Paragraph("End-User Device Compliance Dashboard (EUD) — Automated SLA Ledger", subtitle_style))
    story.append(Spacer(1, 10))
    
    # Meta information block (2-column layout table)
    meta_data = [
        [
            Paragraph(f"<b>Assessment Session:</b> {data['name']}", body_style),
            Paragraph(f"<b>Environment:</b> {data['environment'].upper()}", body_style)
        ],
        [
            Paragraph(f"<b>Overall SLA Compliance Score:</b> {data['overall_score']}%", body_style),
            Paragraph(f"<b>Audit Date:</b> {data['created_at'][:19].replace('T', ' ')}", body_style)
        ]
    ]
    meta_table = Table(meta_data, colWidths=[270, 270])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), bg_light),
        ('PADDING', (0,0), (-1,-1), 8),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 12))
    
    # Evidence Integrity Banner
    integrity_text = "🔒 <b>EVIDENCE CRYPTOGRAPHIC INTEGRITY VERIFIED (PASS):</b> All SHA-256 signatures are authenticated." if data["evidence_integrity_verified"] else "⚠️ <b>INTEGRITY COMPROMISED (FAIL):</b> Evidence database modification or tampering detected!"
    integrity_banner_color = colors.HexColor("#10b981") if data["evidence_integrity_verified"] else colors.HexColor("#ef4444")
    
    integrity_table = Table([[Paragraph(integrity_text, ParagraphStyle('IntTxt', parent=body_style, textColor=integrity_banner_color, fontSize=9))]], colWidths=[540])
    integrity_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f0fdf4") if data["evidence_integrity_verified"] else colors.HexColor("#fef2f2")),
        ('PADDING', (0,0), (-1,-1), 8),
        ('BOX', (0,0), (-1,-1), 0.75, integrity_banner_color),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(integrity_table)
    story.append(Spacer(1, 15))
    
    # Controls Table
    story.append(Paragraph("EVALUATED CONTROL FINDINGS (10 SECURITY MANDATES)", h2_style))
    
    # Header row
    table_data = [
        [
            Paragraph("<b>Code</b>", body_style),
            Paragraph("<b>Control Title</b>", body_style),
            Paragraph("<b>Severity</b>", body_style),
            Paragraph("<b>SLA Status</b>", body_style),
            Paragraph("<b>Details / Remediation Recommendations</b>", body_style)
        ]
    ]
    
    for f in data["findings"]:
        status_color = "#10b981" if f["status"] == "PASS" else "#ef4444"
        sev_color = "#3b82f6" if f["severity"] == "LOW" else "#f59e0b" if f["severity"] == "MEDIUM" else "#ef4444"
        
        status_para = Paragraph(f"<font color='{status_color}'><b>{f['status']}</b></font>", body_style)
        sev_para = Paragraph(f"<font color='{sev_color}'><b>{f['severity']}</b></font>", body_style)
        
        details_str = f"<b>Observation:</b> {f['details'] or ''}<br/><b>Recommendation:</b> {f['recommendation'] or ''}"
        details_para = Paragraph(details_str, ParagraphStyle('DetailsStyle', parent=body_style, fontSize=7.5, leading=9))
        
        table_data.append([
            Paragraph(f"<b>{f['control_code']}</b>", body_style),
            Paragraph(f['control_title'], body_style),
            sev_para,
            status_para,
            details_para
        ])
        
    findings_table = Table(table_data, colWidths=[50, 100, 50, 50, 290])
    findings_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#e2e8f0")),
        ('BOTTOMPADDING', (0,0), (-1,0), 6),
        ('TOPPADDING', (0,0), (-1,0), 6),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('PADDING', (0,1), (-1,-1), 5),
    ]))
    story.append(findings_table)
    story.append(Spacer(1, 15))
    
    # Evidence signatures section
    story.append(Paragraph("IMMUTABLE EVIDENCE LEDGER (SHA-256 NON-REPUDIATION SIGNATURES)", h2_style))
    for ev in data["evidence"]:
        ev_sig_text = f"<b>Source:</b> {ev['source']}  |  <b>Collected:</b> {ev['collected_at']}  |  <b>Signature:</b> {ev['hash_signature']}  |  <b>Integrity Status:</b> {'PASS' if ev['is_verified'] else 'COMPROMISED'}"
        story.append(Paragraph(ev_sig_text, mono_style))
        story.append(Spacer(1, 2))
        
    # Build Document
    doc.build(story)
    
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
