import uuid
import json
from fastapi import APIRouter, Request, Form, UploadFile, File, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import CertificateRequest, CertStatus
from ..ca_ops import parse_csr, ca_exists

router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/", response_class=HTMLResponse)
async def home(request: Request, db: Session = Depends(get_db)):
    ca_ready = ca_exists()
    return templates.TemplateResponse("index.html", {
        "request": request,
        "ca_ready": ca_ready,
    })


@router.get("/generate", response_class=HTMLResponse)
async def generate_page(request: Request):
    return templates.TemplateResponse("generate.html", {"request": request})


@router.get("/submit", response_class=HTMLResponse)
async def submit_form(request: Request):
    if not ca_exists():
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse("submit_csr.html", {
        "request": request,
        "error": None,
        "success": None,
    })


@router.post("/submit")
async def submit_csr(
    request: Request,
    requester_name: str = Form(...),
    requester_email: str = Form(...),
    requester_department: str = Form(""),
    purpose: str = Form(""),
    csr_file: UploadFile = File(...),
    validity_days: int = Form(365),
    db: Session = Depends(get_db),
):
    from fastapi.responses import JSONResponse

    # Detect whether the caller wants JSON (fetch from generate page)
    # or HTML (regular browser form submit from submit_csr page).
    wants_json = "application/json" in request.headers.get("accept", "")

    if not ca_exists():
        if wants_json:
            return JSONResponse({"error": "CA not initialised. Ask your admin to set up the CA first."}, status_code=503)
        return RedirectResponse("/", status_code=302)

    csr_bytes = await csr_file.read()
    if len(csr_bytes) > 64 * 1024:
        if wants_json:
            return JSONResponse({"error": "CSR file too large (max 64 KB)."}, status_code=400)
        return templates.TemplateResponse("submit_csr.html", {
            "request": request, "error": "CSR file too large (max 64KB)", "success": None,
        })

    csr_pem = csr_bytes.decode("utf-8", errors="replace").strip()
    if not csr_pem.startswith("-----BEGIN"):
        if wants_json:
            return JSONResponse({"error": "Invalid CSR format — upload a PEM-encoded .csr file."}, status_code=400)
        return templates.TemplateResponse("submit_csr.html", {
            "request": request, "error": "Invalid CSR format. Please upload a PEM-encoded CSR file.", "success": None,
        })

    try:
        csr_info = parse_csr(csr_pem)
    except ValueError as e:
        if wants_json:
            return JSONResponse({"error": f"CSR validation failed: {e}"}, status_code=400)
        return templates.TemplateResponse("submit_csr.html", {
            "request": request, "error": f"CSR validation failed: {e}", "success": None,
        })

    if validity_days < 1 or validity_days > 3650:
        validity_days = 365

    tracking_id = str(uuid.uuid4())
    cert_req = CertificateRequest(
        tracking_id=tracking_id,
        requester_name=requester_name.strip(),
        requester_email=requester_email.strip().lower(),
        requester_department=requester_department.strip(),
        purpose=purpose.strip(),
        csr_pem=csr_pem,
        common_name=csr_info["common_name"],
        subject_json=json.dumps(csr_info["subject"]),
        sans_json=json.dumps(csr_info["sans"]),
        validity_days=validity_days,
        status=CertStatus.PENDING,
    )
    db.add(cert_req)
    db.commit()

    if wants_json:
        return JSONResponse({"tracking_id": tracking_id, "common_name": csr_info["common_name"]})

    return templates.TemplateResponse("submit_csr.html", {
        "request": request,
        "error": None,
        "success": tracking_id,
        "common_name": csr_info["common_name"],
    })


@router.get("/status", response_class=HTMLResponse)
async def status_page(
    request: Request,
    id: str = "",
    search: str = "",
    db: Session = Depends(get_db),
):
    cert_req = None
    subject = {}
    sans = []
    search_results = []

    if id:
        cert_req = db.query(CertificateRequest).filter(
            CertificateRequest.tracking_id == id
        ).first()
        if cert_req:
            subject = json.loads(cert_req.subject_json or "{}")
            sans = json.loads(cert_req.sans_json or "[]")
    elif search:
        like = f"%{search}%"
        search_results = db.query(CertificateRequest).filter(
            (CertificateRequest.common_name.ilike(like)) |
            (CertificateRequest.requester_name.ilike(like)) |
            (CertificateRequest.requester_email.ilike(like))
        ).order_by(CertificateRequest.submitted_at.desc()).limit(50).all()

    return templates.TemplateResponse("status.html", {
        "request": request,
        "cert_req": cert_req,
        "subject": subject,
        "sans": sans,
        "query_id": id,
        "not_found": bool(id and not cert_req),
        "search": search,
        "search_results": search_results,
    })


@router.get("/download/{tracking_id}")
async def download_cert(tracking_id: str, db: Session = Depends(get_db)):
    cert_req = db.query(CertificateRequest).filter(
        CertificateRequest.tracking_id == tracking_id,
        CertificateRequest.status == CertStatus.ISSUED,
    ).first()

    if not cert_req or not cert_req.certificate_pem:
        raise HTTPException(status_code=404, detail="Certificate not found or not yet issued")

    filename = f"{cert_req.common_name or tracking_id}.crt"
    return Response(
        content=cert_req.certificate_pem,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/trust", response_class=HTMLResponse)
async def trust_page(request: Request):
    from ..ca_ops import ca_exists
    return templates.TemplateResponse("trust.html", {
        "request": request,
        "ca_ready": ca_exists(),
    })


@router.get("/ca.crt")
async def download_ca_cert():
    from ..ca_ops import CA_CERT_PATH
    import os
    if not os.path.exists(CA_CERT_PATH):
        raise HTTPException(status_code=404, detail="CA not initialized")
    with open(CA_CERT_PATH, "rb") as f:
        ca_pem = f.read()
    return Response(
        content=ca_pem,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": 'attachment; filename="ca.crt"'},
    )
