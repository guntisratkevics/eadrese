import datetime as _dt
from typing import Iterable, Optional

from lxml import etree
from lxml.etree import QName
import uuid
from copy import deepcopy
from zeep.helpers import serialize_object
from zeep import ns as zeep_ns, xsd

from ..errors import EAddressSoapError
from ..auth import TokenProvider
from ..soap.client import SoapClient, DIV_NS, SenderDocumentSigner

try:
    import xmlsec
except ImportError:  # pragma: no cover - optional dependency
    xmlsec = None

def confirm_message(
    token_provider: TokenProvider,
    soap_client: SoapClient,
    message_id: str,
    *,
    recipient_eaddresses: Optional[Iterable[str]] = None,
    status: str = "RecipientAccepted",
    status_code: Optional[str] = None,
    status_reason: Optional[str] = None,
) -> bool:
    """Confirm receipt of a message. Returns True on success."""
    token = token_provider.get_token() if token_provider else None
    svc = soap_client.service

    if xmlsec is None:
        raise EAddressSoapError("xmlsec is required to sign confirmations")
    if not soap_client.cfg.certificate or not soap_client.cfg.private_key:
        raise EAddressSoapError("Missing certificate/private_key for confirmation signing")

    confirmation_name = None
    message_envelope = None
    if recipient_eaddresses is None:
        try:
            try:
                msg = svc.GetMessage(Token=token, MessageId=message_id)
            except TypeError:
                msg = svc.GetMessage(MessageId=message_id)
            data = serialize_object(msg) if msg is not None else {}
            confirmation_name = data.get("ConfirmationName")
            recipients = data.get("Recipients") or {}
            if isinstance(recipients, dict):
                recipient_eaddresses = recipients.get("string", [])
            elif isinstance(recipients, list):
                recipient_eaddresses = recipients
            else:
                recipient_eaddresses = []
            if getattr(soap_client, "_history", None) is not None and soap_client._history.last_received:
                try:
                    soap_env = soap_client._history.last_received["envelope"]
                    message_envelope = soap_env.find(f".//{{{DIV_NS}}}Envelope")
                except Exception:
                    message_envelope = None
        except Exception:
            recipient_eaddresses = []
    if not recipient_eaddresses:
        fallback = soap_client.cfg.default_from or ""
        if fallback:
            recipient_eaddresses = [fallback]

    signer = SenderDocumentSigner(
        str(soap_client.cfg.private_key),
        str(soap_client.cfg.certificate),
        str(soap_client.cfg.trust_store_path) if soap_client.cfg.trust_store_path else None,
        sig_hash=soap_client.cfg.sender_sig_hash,
    )

    # Build RecipientConfirmationPart
    part = etree.Element(QName(DIV_NS, "RecipientConfirmationPart"), nsmap={None: DIV_NS})
    confirmations = etree.SubElement(part, QName(DIV_NS, "RecipientConfirmations"))
    entry = etree.SubElement(confirmations, QName(DIV_NS, "ConfirmationEntry"))
    if confirmation_name:
        entry_id = f"{confirmation_name}RecipientSection"
        signature_id = f"{confirmation_name}RecipientSignature"
    else:
        entry_id = f"RecipientConfirmation-{int(_dt.datetime.now().timestamp())}"
        signature_id = f"RecipientSignature-{int(_dt.datetime.now().timestamp())}"
    entry.set("Id", entry_id)
    related = etree.SubElement(entry, QName(DIV_NS, "RelatedRecipients"))
    for addr in recipient_eaddresses:
        if not addr:
            continue
        el = etree.SubElement(related, QName(DIV_NS, "E-Address"))
        el.text = str(addr)
    status_el = etree.SubElement(entry, QName(DIV_NS, "Status"))
    status_el.text = status
    if status_code:
        code_el = etree.SubElement(entry, QName(DIV_NS, "StatusCode"))
        code_el.text = status_code
    if status_reason:
        reason_el = etree.SubElement(entry, QName(DIV_NS, "StatusReason"))
        reason_el.text = status_reason

    signatures = etree.SubElement(part, QName(DIV_NS, "Signatures"))

    # Sign only the confirmation part (RecipientConfirmations + Signatures).
    sign_root = etree.Element(QName(DIV_NS, "RecipientConfirmationPart"), nsmap={None: DIV_NS})
    sign_confirmations = etree.SubElement(sign_root, QName(DIV_NS, "RecipientConfirmations"))
    sign_entry = deepcopy(entry)
    sign_confirmations.append(sign_entry)
    sign_signatures = etree.SubElement(sign_root, QName(DIV_NS, "Signatures"))

    signature = xmlsec.template.create(
        sign_root,
        xmlsec.Transform.C14N,
        signer._sig_transform,
        ns="ds",
    )
    sign_signatures.append(signature)
    ref_recipient = xmlsec.template.add_reference(
        signature, signer._digest_transform, uri=f"#{entry_id}"
    )
    xmlsec.template.add_transform(ref_recipient, xmlsec.Transform.C14N)

    signed_props_suffix = f"{int(_dt.datetime.now().timestamp())}"
    signed_props_id = f"ds-SignedProperties-{signed_props_suffix}"
    signed_props_tag = f"SignedProperties-{signed_props_suffix}"
    ref_props = xmlsec.template.add_reference(
        signature, signer._digest_transform, uri=f"#{signed_props_id}"
    )
    ref_props.set("Type", "http://uri.etsi.org/01903#SignedProperties")

    key_info = xmlsec.template.ensure_key_info(signature)
    key_info.set("Id", "ds-KeyInfo")
    if signer.modulus_b64 and signer.exponent_b64:
        key_value = etree.SubElement(key_info, QName(zeep_ns.DS, "KeyValue"))
        rsa_key_value = etree.SubElement(key_value, QName(zeep_ns.DS, "RSAKeyValue"))
        etree.SubElement(rsa_key_value, QName(zeep_ns.DS, "Modulus")).text = signer.modulus_b64
        etree.SubElement(rsa_key_value, QName(zeep_ns.DS, "Exponent")).text = signer.exponent_b64
    x509_data = etree.SubElement(key_info, QName(zeep_ns.DS, "X509Data"))
    etree.SubElement(x509_data, QName(zeep_ns.DS, "X509Certificate")).text = signer.cert_b64
    if signer.subject_name:
        etree.SubElement(x509_data, QName(zeep_ns.DS, "X509SubjectName")).text = signer.subject_name
    if signer.issuer_name and signer.serial_number:
        issuer_serial = etree.SubElement(x509_data, QName(zeep_ns.DS, "X509IssuerSerial"))
        etree.SubElement(issuer_serial, QName(zeep_ns.DS, "X509IssuerName")).text = signer.issuer_name
        etree.SubElement(issuer_serial, QName(zeep_ns.DS, "X509SerialNumber")).text = signer.serial_number

    signature.set("Id", signature_id)

    xades_ns = "http://uri.etsi.org/01903/v1.3.2#"
    qp = etree.Element(QName(xades_ns, "QualifyingProperties"), nsmap={None: xades_ns})
    qp.set("Target", f"#{signature_id}")
    qp.set("Id", "ds-QualifyingProperties")
    signed_props = etree.SubElement(qp, QName(xades_ns, signed_props_tag))
    signed_props.set("Id", signed_props_id)
    ssp = etree.SubElement(signed_props, QName(xades_ns, "SignedSignatureProperties"))
    signing_time = etree.SubElement(ssp, QName(xades_ns, "SigningTime"))
    signing_time.text = _dt.datetime.now().astimezone().isoformat(timespec="seconds")
    sc = etree.SubElement(ssp, QName(xades_ns, "SigningCertificate"))
    cert_el = etree.SubElement(sc, QName(xades_ns, "Cert"))
    cert_digest = etree.SubElement(cert_el, QName(xades_ns, "CertDigest"))
    etree.SubElement(
        cert_digest,
        QName(zeep_ns.DS, "DigestMethod"),
        Algorithm="http://www.w3.org/2000/09/xmldsig#sha1",
    )
    etree.SubElement(cert_digest, QName(zeep_ns.DS, "DigestValue")).text = signer.cert_sha1_b64
    issuer_serial = etree.SubElement(cert_el, QName(xades_ns, "IssuerSerial"))
    etree.SubElement(issuer_serial, QName(zeep_ns.DS, "X509IssuerName")).text = signer.issuer_name
    etree.SubElement(issuer_serial, QName(zeep_ns.DS, "X509SerialNumber")).text = signer.serial_number
    obj = etree.SubElement(signature, QName(zeep_ns.DS, "Object"))
    obj.append(qp)

    signatures.append(deepcopy(signature))

    # Sign
    ctx = xmlsec.SignatureContext()
    key = xmlsec.Key.from_file(str(soap_client.cfg.private_key), xmlsec.KeyFormat.PEM)
    key.load_cert_from_file(str(soap_client.cfg.certificate), xmlsec.KeyFormat.PEM)
    ctx.key = key
    ctx.register_id(sign_entry, "Id")
    ctx.register_id(signed_props, "Id")
    ctx.sign(signature)

    try:
        if hasattr(svc, "ConfirmMessage"):
            part_any = xsd.AnyObject(xsd.AnyType(), part)
            if token:
                svc.ConfirmMessage(Token=token, MessageId=message_id, RecipientConfirmationPart=part_any)
            else:
                svc.ConfirmMessage(MessageId=message_id, RecipientConfirmationPart=part_any)
        else:
            raise EAddressSoapError("Service has no ConfirmMessage method")
    except Exception as exc:
        # Fallback: build raw SOAP envelope to bypass zeep type validation
        try:
            if getattr(soap_client, "_client", None) is not None:
                soap_env = "http://schemas.xmlsoap.org/soap/envelope/"
                uui_ns = "http://vraa.gov.lv/xmlschemas/div/uui/2011/11"
                envelope = etree.Element(
                    QName(soap_env, "Envelope"),
                    nsmap={"soap": soap_env, "wsa": zeep_ns.WSA, "wsse": zeep_ns.WSSE, "wsu": zeep_ns.WSU, None: uui_ns},
                )
                header = etree.SubElement(envelope, QName(soap_env, "Header"))
                action_el = etree.SubElement(header, QName(zeep_ns.WSA, "Action"))
                action_el.text = "http://vraa.gov.lv/div/uui/2011/11/UnifiedServiceInterface/ConfirmMessage"
                to_el = etree.SubElement(header, QName(zeep_ns.WSA, "To"))
                to_el.text = soap_client.cfg.wsdl_url.replace("?wsdl", "")
                reply_to = etree.SubElement(header, QName(zeep_ns.WSA, "ReplyTo"))
                reply_addr = etree.SubElement(reply_to, QName(zeep_ns.WSA, "Address"))
                reply_addr.text = "http://www.w3.org/2005/08/addressing/anonymous"
                fault_to = etree.SubElement(header, QName(zeep_ns.WSA, "FaultTo"))
                fault_addr = etree.SubElement(fault_to, QName(zeep_ns.WSA, "Address"))
                fault_addr.text = "http://www.w3.org/2005/08/addressing/anonymous"
                msg_id = etree.SubElement(header, QName(zeep_ns.WSA, "MessageID"))
                msg_id.text = f"uuid:{uuid.uuid4()}"

                body = etree.SubElement(envelope, QName(soap_env, "Body"))
                confirm_input = etree.SubElement(body, QName(uui_ns, "ConfirmMessageInput"))
                confirm_input.append(part)
                msg_el = etree.SubElement(confirm_input, QName(uui_ns, "MessageId"))
                msg_el.text = message_id

                http_headers = {}
                if getattr(soap_client, "_wsse", None) is not None:
                    envelope, http_headers = soap_client._wsse.apply(envelope, http_headers)

                address = soap_client.cfg.wsdl_url.replace("?wsdl", "")
                soap_client._client.transport.post_xml(address, envelope, http_headers)
                return True
        except Exception:
            pass
        raise EAddressSoapError(f"VUS ConfirmMessage call failed for {message_id}") from exc
    return True
