from sqlalchemy import Column, Integer, String, Text, DateTime, Enum
from sqlalchemy.sql import func
import enum
from .database import Base


class CertStatus(str, enum.Enum):
    PENDING = "pending"
    ISSUED = "issued"
    REVOKED = "revoked"
    REJECTED = "rejected"


class CertificateRequest(Base):
    __tablename__ = "certificate_requests"

    id = Column(Integer, primary_key=True, index=True)
    tracking_id = Column(String(36), unique=True, index=True, nullable=False)

    # Requester info
    requester_name = Column(String(255), nullable=False)
    requester_email = Column(String(255), nullable=False)
    requester_department = Column(String(255))
    purpose = Column(Text)

    # CSR data
    csr_pem = Column(Text, nullable=False)
    common_name = Column(String(255))
    subject_json = Column(Text)  # JSON of full subject
    sans_json = Column(Text)     # JSON array of SANs

    # Certificate data (populated after signing)
    certificate_pem = Column(Text)
    serial_number = Column(String(64))
    validity_days = Column(Integer, default=365)

    # Status & timestamps
    status = Column(String(20), default=CertStatus.PENDING)
    submitted_at = Column(DateTime, server_default=func.now())
    reviewed_at = Column(DateTime)
    issued_at = Column(DateTime)
    expires_at = Column(DateTime)
    revoked_at = Column(DateTime)

    # Admin notes
    admin_notes = Column(Text)
    revocation_reason = Column(String(255))
