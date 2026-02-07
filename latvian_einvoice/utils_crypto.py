import base64
import os
import ssl
from pathlib import Path
from typing import Optional, Tuple
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def load_cert_bytes(cert_path: Path | str | bytes) -> bytes:
    if isinstance(cert_path, (str, Path)):
        return Path(cert_path).read_bytes()
    return cert_path


def thumbprint_sha1_b64(cert_pem: bytes) -> str:
    der = ssl.PEM_cert_to_DER_cert(cert_pem.decode("utf-8"))
    digest = hashes.Hash(hashes.SHA1())
    digest.update(der)
    return base64.b64encode(digest.finalize()).decode("ascii")


def encrypt_key_for_recipient(cert_pem: bytes, key_bytes: bytes) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
    public_key = cert.public_key()
    encrypted = public_key.encrypt(key_bytes, asym_padding.PKCS1v15())
    return base64.b64encode(encrypted).decode("ascii")


def encrypt_key_for_recipient_oaep_sha1(cert_pem: bytes, key_bytes: bytes) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
    public_key = cert.public_key()
    encrypted = public_key.encrypt(
        key_bytes,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )
    return base64.b64encode(encrypted).decode("ascii")


def generate_symmetric_key(length: int = 32) -> bytes:
    return os.urandom(length)


def derive_encryption_fields(
    *,
    recipient_cert_path: Optional[Path] = None,
    recipient_cert_pem: Optional[bytes] = None,
    key_bytes: Optional[bytes] = None,
    iv_bytes: Optional[bytes] = None,
    mode: str = "gcm",
) -> Tuple[str, str, bytes, Optional[bytes]]:
    if not recipient_cert_pem:
        if not recipient_cert_path:
            raise ValueError("Recipient certificate is required for EncryptionInfo")
        recipient_cert_pem = load_cert_bytes(recipient_cert_path)
    key = key_bytes or generate_symmetric_key()
    thumb_b64 = thumbprint_sha1_b64(recipient_cert_pem)
    if mode.lower() in ("oaep_cbc", "cbc"):
        iv = iv_bytes or os.urandom(16)
        key_blob = build_div_key_blob(key, iv)
        enc_key_b64 = encrypt_key_for_recipient_oaep_sha1(recipient_cert_pem, key_blob)
        return enc_key_b64, thumb_b64, key, iv
    enc_key_b64 = encrypt_key_for_recipient(recipient_cert_pem, key)
    return enc_key_b64, thumb_b64, key, None


def encrypt_payload_aes_gcm(key: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
    """Returns (iv, ciphertext_with_tag)."""
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(iv, plaintext, aad)
    return iv, ct


def encrypt_payload_aes_cbc_pkcs5(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def decrypt_key_with_private(private_key_pem: bytes, enc_key_b64: str) -> bytes:
    private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
    return private_key.decrypt(base64.b64decode(enc_key_b64), asym_padding.PKCS1v15())


def decrypt_key_with_private_oaep_sha1(private_key_pem: bytes, enc_key_b64: str) -> bytes:
    private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
    return private_key.decrypt(
        base64.b64decode(enc_key_b64),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )


def decrypt_payload_aes_gcm(key: bytes, iv: bytes, ciphertext_with_tag: bytes, aad: bytes = b"") -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext_with_tag, aad)


def decrypt_payload_aes_cbc_pkcs5(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def build_div_key_blob(key: bytes, iv: bytes) -> bytes:
    return len(key).to_bytes(4, "big") + key + iv


def _decode_modexp(value: str) -> int:
    raw = None
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:
        raw = None
    if raw:
        return int.from_bytes(raw, "big")
    try:
        return int(value, 16)
    except Exception as exc:
        raise ValueError("Invalid modulus/exponent encoding") from exc


def rsa_public_key_from_modexp(modulus_b64: str, exponent_b64: str) -> rsa.RSAPublicKey:
    modulus = _decode_modexp(modulus_b64)
    exponent = _decode_modexp(exponent_b64)
    public_numbers = rsa.RSAPublicNumbers(exponent, modulus)
    return public_numbers.public_key(default_backend())


def encrypt_key_blob_oaep_sha1(public_key: rsa.RSAPublicKey, key_blob: bytes) -> str:
    encrypted = public_key.encrypt(
        key_blob,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )
    return base64.b64encode(encrypted).decode("ascii")


# Optional OCSP validation (best-effort)
def validate_chain_with_ocsp(cert_pem: bytes, chain_pem: list[bytes]) -> bool:
    """
    Lightweight OCSP check: returns True if at least one OCSP response validates,
    False otherwise. Network required. Best-effort; failures return False.
    """
    try:
        from cryptography.x509 import ocsp, load_pem_x509_certificate
        from cryptography.hazmat.primitives import hashes
        import requests

        leaf = load_pem_x509_certificate(cert_pem)
        issuer = load_pem_x509_certificate(chain_pem[0]) if chain_pem else None
        if not issuer:
            return False
        aia = leaf.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value
        ocsp_uris = [d.access_location.value for d in aia if d.access_method == x509.oid.AuthorityInformationAccessOID.OCSP]
        if not ocsp_uris:
            return False
        builder = ocsp.OCSPRequestBuilder().add_certificate(leaf, issuer, hashes.SHA1())
        req = builder.build()
        for uri in ocsp_uris:
            try:
                r = requests.post(uri, data=req.public_bytes(), headers={"Content-Type": "application/ocsp-request"}, timeout=5)
                resp = ocsp.load_der_ocsp_response(r.content)
                if resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL and resp.certificate_status == ocsp.OCSPCertStatus.GOOD:
                    return True
            except Exception:
                continue
    except Exception:
        return False
    return False
