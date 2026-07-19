import json
import time
import datetime
from fastapi import APIRouter, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func

from ..database import get_db
from ..models import CertificateRequest, CertStatus
from ..ca_ops import ca_exists, init_ca, sign_csr, get_ca_info, generate_crl, parse_csr
from ..auth import create_session_token, verify_session_token, check_password

router = APIRouter(prefix="/admin")
templates = Jinja2Templates(directory="templates")

REVOCATION_REASONS = [
    "Unspecified",
    "Key Compromise",
    "CA Compromise",
    "Affiliation Changed",
    "Superseded",
    "Cessation of Operation",
    "Certificate Hold",
]


# --- Login brute-force throttling (in-memory; single uvicorn worker) ---
_LOGIN_WINDOW = 300      # seconds
_LOGIN_MAX_FAILS = 5     # failed attempts per window per client IP
_login_fails: dict[str, list[float]] = {}


def _client_ip(request: Request) -> str:
    # Behind the nginx proxy the real client IP is forwarded; fall back safely.
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _login_rate_limited(ip: str) -> bool:
    now = time.time()
    recent = [t for t in _login_fails.get(ip, []) if now - t < _LOGIN_WINDOW]
    _login_fails[ip] = recent
    return len(recent) >= _LOGIN_MAX_FAILS


def _record_login_failure(ip: str) -> None:
    _login_fails.setdefault(ip, []).append(time.time())


def get_admin(request: Request):
    token = request.cookies.get("session")
    if not token or not verify_session_token(token):
        return None
    return True


def require_admin(request: Request):
    if not get_admin(request):
        raise HTTPException(status_code=302, headers={"Location": "/admin/login"})
    return True


# --- Auth ---

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if get_admin(request):
        return RedirectResponse("/admin/dashboard", status_code=302)
    return templates.TemplateResponse("admin/login.html", {"request": request, "error": None})


@router.post("/login", response_class=HTMLResponse)
async def login(request: Request, password: str = Form(...)):
    ip = _client_ip(request)
    if _login_rate_limited(ip):
        return templates.TemplateResponse("admin/login.html", {
            "request": request,
            "error": "Too many failed attempts. Please wait a few minutes and try again.",
        }, status_code=429)

    if check_password(password):
        _login_fails.pop(ip, None)  # reset on success
        token = create_session_token()
        response = RedirectResponse("/admin/dashboard", status_code=302)
        response.set_cookie(
            "session", token,
            httponly=True, secure=True, samesite="lax", max_age=3600 * 8,
        )
        return response

    _record_login_failure(ip)
    return templates.TemplateResponse("admin/login.html", {
        "request": request,
        "error": "Invalid password",
    }, status_code=401)


@router.get("/logout")
async def logout():
    response = RedirectResponse("/admin/login", status_code=302)
    response.delete_cookie("session", httponly=True, secure=True, samesite="lax")
    return response


# --- CA Setup ---

@router.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request, _=Depends(require_admin)):
    if ca_exists():
        return RedirectResponse("/admin/dashboard", status_code=302)
    return templates.TemplateResponse("admin/setup.html", {"request": request, "error": None})


@router.post("/setup", response_class=HTMLResponse)
async def setup_ca(
    request: Request,
    ca_cn: str = Form(...),
    ca_org: str = Form(...),
    ca_country: str = Form(...),
    validity_days: int = Form(3650),
    _=Depends(require_admin),
):
    if ca_exists():
        return RedirectResponse("/admin/dashboard", status_code=302)
    try:
        init_ca(common_name=ca_cn, org=ca_org, country=ca_country, validity_days=validity_days)
        return RedirectResponse("/admin/dashboard", status_code=302)
    except Exception as e:
        return templates.TemplateResponse("admin/setup.html", {
            "request": request,
            "error": str(e),
        })


# --- Dashboard ---

@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    search: str = "",
    db: Session = Depends(get_db),
    _=Depends(require_admin),
):
    if not ca_exists():
        return RedirectResponse("/admin/setup", status_code=302)

    counts = {
        "pending": db.query(func.count(CertificateRequest.id)).filter(CertificateRequest.status == CertStatus.PENDING).scalar(),
        "issued": db.query(func.count(CertificateRequest.id)).filter(CertificateRequest.status == CertStatus.ISSUED).scalar(),
        "revoked": db.query(func.count(CertificateRequest.id)).filter(CertificateRequest.status == CertStatus.REVOKED).scalar(),
        "rejected": db.query(func.count(CertificateRequest.id)).filter(CertificateRequest.status == CertStatus.REJECTED).scalar(),
    }

    now = datetime.datetime.now(datetime.timezone.utc)
    expiring_soon = db.query(CertificateRequest).filter(
        CertificateRequest.status == CertStatus.ISSUED,
        CertificateRequest.expires_at <= (now + datetime.timedelta(days=30)),
        CertificateRequest.expires_at > now,
    ).order_by(CertificateRequest.expires_at).limit(5).all()

    recent_query = db.query(CertificateRequest)
    if search:
        like = f"%{search}%"
        recent_query = recent_query.filter(
            (CertificateRequest.common_name.ilike(like)) |
            (CertificateRequest.requester_name.ilike(like)) |
            (CertificateRequest.requester_email.ilike(like))
        )
    recent_query = recent_query.order_by(CertificateRequest.submitted_at.desc())
    recent = recent_query.limit(20 if search else 8).all()
    recent_total = recent_query.count() if search else None

    ca_info = get_ca_info()

    return templates.TemplateResponse("admin/dashboard.html", {
        "request": request,
        "counts": counts,
        "expiring_soon": expiring_soon,
        "recent": recent,
        "recent_total": recent_total,
        "search": search,
        "ca_info": ca_info,
        "now_dt": now,
    })


# --- Pending Requests ---

@router.get("/pending", response_class=HTMLResponse)
async def pending_list(
    request: Request,
    search: str = "",
    page: int = 1,
    db: Session = Depends(get_db),
    _=Depends(require_admin),
):
    query = db.query(CertificateRequest).filter(
        CertificateRequest.status == CertStatus.PENDING
    )
    if search:
        like = f"%{search}%"
        query = query.filter(
            (CertificateRequest.common_name.ilike(like)) |
            (CertificateRequest.requester_name.ilike(like)) |
            (CertificateRequest.requester_email.ilike(like))
        )
    query = query.order_by(CertificateRequest.submitted_at.asc())

    total = query.count()
    total_pages = max(1, (total + _PER_PAGE - 1) // _PER_PAGE)
    page = max(1, min(page, total_pages))
    requests = query.offset((page - 1) * _PER_PAGE).limit(_PER_PAGE).all()

    return templates.TemplateResponse("admin/pending.html", {
        "request": request,
        "requests": requests,
        "search": search,
        "page": page,
        "total": total,
        "total_pages": total_pages,
        "per_page": _PER_PAGE,
        "page_range": _page_range(page, total_pages),
    })


# --- All Certificates ---

_PER_PAGE = 20


def _page_range(page: int, total_pages: int) -> list:
    if total_pages <= 7:
        return list(range(1, total_pages + 1))
    pages: list = [1]
    w_start = max(2, page - 1)
    w_end = min(total_pages - 1, page + 1)
    if w_start > 2:
        pages.append(None)
    pages.extend(range(w_start, w_end + 1))
    if w_end < total_pages - 1:
        pages.append(None)
    pages.append(total_pages)
    return pages


@router.get("/certificates", response_class=HTMLResponse)
async def certificates_list(
    request: Request,
    status: str = "",
    search: str = "",
    page: int = 1,
    db: Session = Depends(get_db),
    _=Depends(require_admin),
):
    query = db.query(CertificateRequest)
    if status:
        query = query.filter(CertificateRequest.status == status)
    if search:
        like = f"%{search}%"
        query = query.filter(
            (CertificateRequest.common_name.ilike(like)) |
            (CertificateRequest.requester_name.ilike(like)) |
            (CertificateRequest.requester_email.ilike(like))
        )
    query = query.order_by(CertificateRequest.submitted_at.desc())

    total = query.count()
    total_pages = max(1, (total + _PER_PAGE - 1) // _PER_PAGE)
    page = max(1, min(page, total_pages))
    certs = query.offset((page - 1) * _PER_PAGE).limit(_PER_PAGE).all()

    return templates.TemplateResponse("admin/certificates.html", {
        "request": request,
        "certs": certs,
        "filter_status": status,
        "search": search,
        "statuses": list(CertStatus),
        "page": page,
        "total": total,
        "total_pages": total_pages,
        "per_page": _PER_PAGE,
        "page_range": _page_range(page, total_pages),
        "now_naive": datetime.datetime.utcnow(),
    })


# --- Certificate Detail ---

@router.get("/certificate/{cert_id}", response_class=HTMLResponse)
async def certificate_detail(
    cert_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(require_admin),
):
    cert_req = db.query(CertificateRequest).filter(CertificateRequest.id == cert_id).first()
    if not cert_req:
        raise HTTPException(status_code=404, detail="Request not found")

    subject = json.loads(cert_req.subject_json or "{}")
    sans = json.loads(cert_req.sans_json or "[]")

    return templates.TemplateResponse("admin/certificate_detail.html", {
        "request": request,
        "cert_req": cert_req,
        "subject": subject,
        "sans": sans,
        "revocation_reasons": REVOCATION_REASONS,
        "now_naive": datetime.datetime.utcnow(),
    })


# --- Sign Certificate ---

@router.post("/certificate/{cert_id}/sign", response_class=HTMLResponse)
async def sign_certificate(
    cert_id: int,
    request: Request,
    admin_notes: str = Form(""),
    db: Session = Depends(get_db),
    _=Depends(require_admin),
):
    cert_req = db.query(CertificateRequest).filter(CertificateRequest.id == cert_id).first()
    if not cert_req:
        raise HTTPException(status_code=404, detail="Request not found")

    if cert_req.status != CertStatus.PENDING:
        raise HTTPException(status_code=400, detail="Only pending requests can be signed")

    try:
        cert_pem, serial, issued_at, expires_at = sign_csr(cert_req.csr_pem, cert_req.validity_days or 365)
    except Exception as e:
        subject = json.loads(cert_req.subject_json or "{}")
        sans = json.loads(cert_req.sans_json or "[]")
        return templates.TemplateResponse("admin/certificate_detail.html", {
            "request": request,
            "cert_req": cert_req,
            "subject": subject,
            "sans": sans,
            "revocation_reasons": REVOCATION_REASONS,
            "error": f"Signing failed: {e}",
        })

    now = datetime.datetime.now(datetime.timezone.utc)
    cert_req.certificate_pem = cert_pem
    cert_req.serial_number = str(serial)
    cert_req.issued_at = issued_at
    cert_req.expires_at = expires_at
    cert_req.reviewed_at = now
    cert_req.status = CertStatus.ISSUED
    cert_req.admin_notes = admin_notes.strip() or cert_req.admin_notes
    db.commit()

    return RedirectResponse(f"/admin/certificate/{cert_id}", status_code=302)


# --- Reject Request ---

@router.post("/certificate/{cert_id}/reject")
async def reject_certificate(
    cert_id: int,
    request: Request,
    admin_notes: str = Form(""),
    db: Session = Depends(get_db),
    _=Depends(require_admin),
):
    cert_req = db.query(CertificateRequest).filter(CertificateRequest.id == cert_id).first()
    if not cert_req:
        raise HTTPException(status_code=404, detail="Not found")

    if cert_req.status != CertStatus.PENDING:
        raise HTTPException(status_code=400, detail="Only pending requests can be rejected")

    now = datetime.datetime.now(datetime.timezone.utc)
    cert_req.status = CertStatus.REJECTED
    cert_req.reviewed_at = now
    cert_req.admin_notes = admin_notes.strip()
    db.commit()

    return RedirectResponse(f"/admin/certificate/{cert_id}", status_code=302)


# --- Revoke Certificate ---

@router.post("/certificate/{cert_id}/revoke")
async def revoke_certificate(
    cert_id: int,
    request: Request,
    revocation_reason: str = Form("Unspecified"),
    admin_notes: str = Form(""),
    db: Session = Depends(get_db),
    _=Depends(require_admin),
):
    cert_req = db.query(CertificateRequest).filter(CertificateRequest.id == cert_id).first()
    if not cert_req:
        raise HTTPException(status_code=404, detail="Not found")

    if cert_req.status != CertStatus.ISSUED:
        raise HTTPException(status_code=400, detail="Only issued certificates can be revoked")

    now = datetime.datetime.now(datetime.timezone.utc)
    cert_req.status = CertStatus.REVOKED
    cert_req.revoked_at = now
    cert_req.revocation_reason = revocation_reason
    if admin_notes:
        cert_req.admin_notes = admin_notes.strip()
    db.commit()

    return RedirectResponse(f"/admin/certificate/{cert_id}", status_code=302)


# --- Delete Revoked Certificate ---

@router.post("/certificate/{cert_id}/delete")
async def delete_certificate(
    cert_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(require_admin),
):
    cert_req = db.query(CertificateRequest).filter(CertificateRequest.id == cert_id).first()
    if not cert_req:
        raise HTTPException(status_code=404, detail="Not found")

    # Only pending, revoked, or rejected records may be permanently deleted
    # (an issued cert must be revoked first).
    if cert_req.status not in (CertStatus.PENDING, CertStatus.REVOKED, CertStatus.REJECTED):
        raise HTTPException(status_code=400, detail="Only pending, revoked, or rejected certificates can be deleted")

    # A revoked cert must stay on the CRL until it expires; removing it early
    # would silently un-revoke it. Pending and rejected requests were never issued
    # (no serial, not on the CRL), so they can be deleted at any time.
    if cert_req.status == CertStatus.REVOKED:
        now = datetime.datetime.utcnow()
        if cert_req.expires_at is None or cert_req.expires_at > now:
            raise HTTPException(
                status_code=400,
                detail="A revoked certificate can only be deleted after it has expired",
            )

    status_value = getattr(cert_req.status, "value", cert_req.status)
    db.delete(cert_req)
    db.commit()

    # Pending records live on their own workflow page; everything else returns
    # to the unfiltered certificates list (no status pre-selected in the filter).
    if status_value == CertStatus.PENDING.value:
        return RedirectResponse("/admin/pending", status_code=302)
    return RedirectResponse("/admin/certificates", status_code=302)


# --- CA Info ---

@router.get("/ca-info", response_class=HTMLResponse)
async def ca_info_page(request: Request, _=Depends(require_admin)):
    ca_info = get_ca_info()
    return templates.TemplateResponse("admin/ca_info.html", {
        "request": request,
        "ca_info": ca_info,
    })


# --- CRL Download ---

@router.get("/crl.pem")
async def download_crl(db: Session = Depends(get_db), _=Depends(require_admin)):
    revoked = db.query(CertificateRequest).filter(
        CertificateRequest.status == CertStatus.REVOKED,
        CertificateRequest.serial_number.isnot(None),
    ).all()

    entries = [{"serial": r.serial_number, "revoked_at": r.revoked_at} for r in revoked]
    crl_pem = generate_crl(entries)

    return Response(
        content=crl_pem,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": 'attachment; filename="crl.pem"'},
    )
