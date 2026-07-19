import os
import json
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

CA_DIR = os.getenv("CA_DATA_DIR", "/ca-data")
CA_CERT_PATH = os.path.join(CA_DIR, "ca.crt")
CA_KEY_PATH = os.path.join(CA_DIR, "ca.key")
CA_SERIAL_PATH = os.path.join(CA_DIR, "serial")


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def ca_exists() -> bool:
    return os.path.exists(CA_CERT_PATH) and os.path.exists(CA_KEY_PATH)


def init_ca(common_name: str, org: str, country: str, validity_days: int = 3650) -> None:
    os.makedirs(CA_DIR, exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country[:2].upper()),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = _utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(key, hashes.SHA256())
    )

    with open(CA_KEY_PATH, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    os.chmod(CA_KEY_PATH, 0o600)

    with open(CA_CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(CA_SERIAL_PATH, "w") as f:
        f.write("1000")


def load_ca():
    with open(CA_KEY_PATH, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    with open(CA_CERT_PATH, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    return key, cert


def _next_serial() -> int:
    with open(CA_SERIAL_PATH, "r") as f:
        serial = int(f.read().strip())
    with open(CA_SERIAL_PATH, "w") as f:
        f.write(str(serial + 1))
    return serial


def parse_csr(csr_pem: str) -> dict:
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
    except Exception as e:
        raise ValueError(f"Invalid CSR: {e}")

    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid")

    subject = {}
    attr_map = {
        "commonName": "Common Name",
        "organizationName": "Organization",
        "organizationalUnitName": "Org Unit",
        "countryName": "Country",
        "stateOrProvinceName": "State",
        "localityName": "Locality",
        "emailAddress": "Email",
    }
    for attr in csr.subject:
        raw = attr.oid._name
        subject[raw] = attr.value

    sans = []
    try:
        san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                sans.append(f"DNS:{name.value}")
            elif isinstance(name, x509.IPAddress):
                sans.append(f"IP:{name.value}")
            elif isinstance(name, x509.RFC822Name):
                sans.append(f"email:{name.value}")
    except x509.ExtensionNotFound:
        pass

    return {
        "subject": subject,
        "common_name": subject.get("commonName", ""),
        "sans": sans,
        "subject_label_map": attr_map,
    }


def sign_csr(csr_pem: str, validity_days: int = 365) -> tuple:
    ca_key, ca_cert = load_ca()
    csr = x509.load_pem_x509_csr(csr_pem.encode())

    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid")

    serial = _next_serial()
    now = _utcnow()
    not_after = now + datetime.timedelta(days=validity_days)

    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_encipherment=True, content_commitment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH,
            ExtendedKeyUsageOID.CLIENT_AUTH,
        ]), critical=False)
    )

    try:
        san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        builder = builder.add_extension(san_ext.value, critical=False)
    except x509.ExtensionNotFound:
        pass

    cert = builder.sign(ca_key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return cert_pem, serial, now, not_after


def get_ca_info() -> dict | None:
    if not ca_exists():
        return None
    _, ca_cert = load_ca()
    with open(CA_CERT_PATH, "rb") as f:
        ca_pem = f.read().decode()

    subject = {}
    for attr in ca_cert.subject:
        subject[attr.oid._name] = attr.value

    return {
        "subject": subject,
        "common_name": subject.get("commonName", ""),
        "org": subject.get("organizationName", ""),
        "country": subject.get("countryName", ""),
        "serial": hex(ca_cert.serial_number),
        "not_before": ca_cert.not_valid_before_utc,
        "not_after": ca_cert.not_valid_after_utc,
        "pem": ca_pem,
    }


def generate_crl(revoked_entries: list) -> bytes:
    ca_key, ca_cert = load_ca()
    now = _utcnow()

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=7))
    )

    for entry in revoked_entries:
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(int(entry["serial"], 16) if isinstance(entry["serial"], str) and entry["serial"].startswith("0x") else int(entry["serial"]))
            .revocation_date(entry["revoked_at"])
            .build()
        )
        builder = builder.add_revoked_certificate(revoked)

    crl = builder.sign(ca_key, hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.PEM)
