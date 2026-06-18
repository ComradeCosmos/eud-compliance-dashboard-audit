from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, HTMLResponse
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.reports import services as reports_services

router = APIRouter(prefix="/api/reports", tags=["Compliance Reporting"])

@router.get("/{assessment_id}/json")
def get_json_report(assessment_id: int, db: Session = Depends(get_db)):
    """Generates and returns the full compliance report in JSON format."""
    try:
        return reports_services.generate_json_report(db, assessment_id)
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate JSON report: {str(e)}")

@router.get("/{assessment_id}/html", response_class=HTMLResponse)
def get_html_report(assessment_id: int, db: Session = Depends(get_db)):
    """Generates and returns the compliance report rendered as a styled HTML page."""
    try:
        return reports_services.generate_html_report(db, assessment_id)
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate HTML report: {str(e)}")

@router.get("/{assessment_id}/pdf")
def get_pdf_report(assessment_id: int, db: Session = Depends(get_db)):
    """Generates and downloads a print-ready PDF compliance audit report."""
    try:
        pdf_content = reports_services.generate_pdf_report(db, assessment_id)
        return Response(
            content=pdf_content,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=EUD_Report_Assessment_{assessment_id}.pdf"
            }
        )
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF report: {str(e)}")
streamable = True
