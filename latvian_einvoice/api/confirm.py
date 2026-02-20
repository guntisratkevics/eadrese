import datetime as _dt
import base64
import os
from pathlib import Path
from typing import Iterable, Mapping, Optional

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
try:
    from cryptography.hazmat.primitives.asymmetric import padding as _padding
    from cryptography.hazmat.primitives import hashes as _hashes
except ImportError:  # pragma: no cover - optional dependency
    _padding = None
    _hashes = None

_NETIFY_XSL = b"""<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:xades1="http://uri.etsi.org/01903/v1.1.1#"
                xmlns:xades3="http://uri.etsi.org/01903/v1.3.2#"
                xmlns:uui="http://vraa.gov.lv/xmlschemas/div/uui/2011/11"
                xmlns:cm="http://ivis.eps.gov.lv/XMLSchemas/100001/DIV/v1-0"
                xmlns:exsl="http://exslt.org/common"
                xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                extension-element-prefixes="exsl"
                exclude-result-prefixes="exsl cm xades1 xades3 uui ds">
    <xsl:output method="xml" omit-xml-declaration="yes" indent="no"/>
    <xsl:strip-space elements="*"/>

    <xsl:template match="@* | text() | comment() | processing-instruction()">
        <xsl:copy/>
    </xsl:template>
    <xsl:template match="*">
        <xsl:element name="{name()}" namespace="{namespace-uri()}">
            <xsl:apply-templates select="@* | node()"/>
        </xsl:element>
    </xsl:template>
    <xsl:template match="uui:*">
        <xsl:element name="{local-name()}" namespace="{namespace-uri()}">
            <xsl:apply-templates select="@* | node()"/>
        </xsl:element>
    </xsl:template>
    <xsl:template match="cm:AddressLVA">
        <xsl:variable name="dummy">
            <AddressLVA xmlns:a="http://ivis.eps.gov.lv/XMLSchemas/100001/Address/v1-1">
                <xsl:apply-templates select="@* | node()"/>
            </AddressLVA>
        </xsl:variable>
        <xsl:copy-of select="exsl:node-set($dummy)/*"/>
    </xsl:template>
    <xsl:template match="cm:AddressLVA/*">
        <xsl:element name="a:{local-name()}"
                     namespace="http://ivis.eps.gov.lv/XMLSchemas/100001/Address/v1-1">
            <xsl:apply-templates select="@* | node()"/>
        </xsl:element>
    </xsl:template>
    <xsl:template match="xades1:QualifyingProperties">
        <xsl:element name="{local-name()}"
                     namespace="http://uri.etsi.org/01903/v1.1.1#">
            <xsl:copy-of select="@*"/>
            <xsl:apply-templates/>
        </xsl:element>
    </xsl:template>
    <xsl:template match="xades3:QualifyingProperties">
        <xsl:element name="{local-name()}"
                     namespace="http://uri.etsi.org/01903/v1.3.2#">
            <xsl:copy-of select="@*"/>
            <xsl:apply-templates/>
        </xsl:element>
    </xsl:template>
    <xsl:template match="ds:Reference/ds:DigestValue/text()">
      <xsl:choose>
        <xsl:when test="contains(.,'&#xA;') or string-length(.) &lt; 77"><xsl:value-of select="."/></xsl:when>
        <xsl:otherwise><xsl:value-of select="concat(substring(.,1, 76),'&#xA;',substring(.,77))"/></xsl:otherwise></xsl:choose></xsl:template>
</xsl:stylesheet>
"""
_NETIFY_TRANSFORM = etree.XSLT(etree.XML(_NETIFY_XSL))

def _netify_envelope(envelope: etree._Element) -> etree._Element:
    """Apply the Java netify XSLT (libxslt-compatible) to the envelope."""
    try:
        result = _NETIFY_TRANSFORM(envelope)
        return result.getroot()
    except Exception:
        return envelope

def _combine_envelope_parts(
    root_element: str,
    parts: Iterable[etree._Element],
    *,
    include_existing_signatures: bool = True,
) -> etree._Element:
    """Combine DIV envelope parts the same way as the Java client."""
    sender_doc = None
    server_doc = None
    recipient_confirmations = []
    signatures = []
    ns = {"en": DIV_NS, "ds": zeep_ns.DS}

    for xml in parts:
        if xml is None:
            continue
        current_root = QName(xml).localname
        can_sender = False
        can_server = False
        can_confirm = False
        if current_root == "Envelope":
            can_sender = True
            can_server = True
            can_confirm = True
        elif current_root == "ServerConfirmationPart":
            can_server = True
        elif current_root == "RecipientConfirmationPart":
            can_confirm = True
        elif current_root == "Signature":
            if include_existing_signatures:
                signatures.append(xml)
            continue
        else:
            raise EAddressSoapError(f"Unsupported DIV part root: {current_root}")

        has_info = False
        if can_sender:
            nodes = xml.xpath("./en:SenderDocument", namespaces=ns)
            if nodes:
                has_info = True
                if sender_doc is not None:
                    raise EAddressSoapError("SenderDocument already defined in envelope parts")
                sender_doc = nodes[0]
        if can_server:
            nodes = xml.xpath("./en:ServerTransportMetadata", namespaces=ns)
            if nodes:
                has_info = True
                if server_doc is not None:
                    raise EAddressSoapError("ServerTransportMetadata already defined in envelope parts")
                server_doc = nodes[0]
        if can_confirm:
            confirm_nodes = xml.xpath(
                "./en:RecipientConfirmations/en:ConfirmationEntry", namespaces=ns
            )
            if confirm_nodes:
                has_info = True
                recipient_confirmations.extend(confirm_nodes)
        sig_nodes = xml.xpath("./en:Signatures/ds:Signature", namespaces=ns)
        if sig_nodes and include_existing_signatures:
            has_info = True
            signatures.extend(sig_nodes)
        if not has_info:
            raise EAddressSoapError(f"Envelope part {current_root} has no usable content")

    combined = etree.Element(QName(DIV_NS, root_element), nsmap={None: DIV_NS})
    if sender_doc is not None:
        combined.append(deepcopy(sender_doc))
    if server_doc is not None:
        combined.append(deepcopy(server_doc))
    if recipient_confirmations:
        confirms_el = etree.SubElement(combined, QName(DIV_NS, "RecipientConfirmations"))
        for entry in recipient_confirmations:
            confirms_el.append(deepcopy(entry))
    if signatures:
        sigs_el = etree.SubElement(combined, QName(DIV_NS, "Signatures"))
        for sig in signatures:
            sigs_el.append(deepcopy(sig))
    return combined

def _find_by_id(root: etree._Element, id_value: str) -> Optional[etree._Element]:
    matches = root.xpath(".//*[@Id=$id]", id=id_value)
    return matches[0] if matches else None


def _extract_section_digest_hints(envelope: Optional[etree._Element]) -> dict[str, str]:
    """Extract Sender/Server section digests from the source envelope signatures."""
    hints: dict[str, str] = {}
    if envelope is None:
        return hints
    try:
        refs = envelope.xpath(".//ds:Reference[@URI]", namespaces={"ds": zeep_ns.DS})
    except Exception:
        return hints
    for ref in refs:
        uri = (ref.get("URI") or "").strip()
        if not uri.startswith("#"):
            continue
        section_id = uri[1:]
        if section_id not in {"SenderSection", "ServerSection"}:
            continue
        if section_id in hints:
            continue
        digest_value = ref.find(f".//{{{zeep_ns.DS}}}DigestValue")
        digest_text = (digest_value.text or "").strip() if digest_value is not None else ""
        if digest_text:
            hints[section_id] = digest_text
    return hints


def _wrap_digest_text(value: str) -> str:
    text = (value or "").strip()
    if not text or "\n" in text:
        return text
    if len(text) <= 76:
        return text
    chunks = [text[i:i + 76] for i in range(0, len(text), 76)]
    return "\n".join(chunks)


def _strip_whitespace_text_nodes(root: etree._Element) -> None:
    for node in root.iter():
        if node.text is not None and not node.text.strip():
            node.text = None
        if node.tail is not None and not node.tail.strip():
            node.tail = None


def _sign_combined_envelope(
    combined: etree._Element,
    signer: SenderDocumentSigner,
    signature_id: str,
    signed_section_ids: Iterable[str],
    section_digest_hints: Optional[Mapping[str, str]] = None,
) -> etree._Element:
    signatures = combined.find(f".//{{{DIV_NS}}}Signatures")
    if signatures is None:
        signatures = etree.SubElement(combined, QName(DIV_NS, "Signatures"))

    signature = xmlsec.template.create(
        combined,
        xmlsec.Transform.C14N,
        signer._sig_transform,
        ns="ds",
    )
    signatures.append(signature)

    ref_nodes = {}
    for section_id in signed_section_ids:
        ref = xmlsec.template.add_reference(
            signature, signer._digest_transform, uri=f"#{section_id}"
        )
        xmlsec.template.add_transform(ref, xmlsec.Transform.C14N)
        ref_nodes[section_id] = ref

    signed_props_suffix = f"{uuid.uuid4().int % 100000000:08d}"
    signed_props_id = f"ds-SignedProperties-{signed_props_suffix}"
    signed_props_tag = f"SignedProperties-{signed_props_suffix}"
    signature_value_id = f"ds-SignatureValue-{uuid.uuid4().int % 100000000:08d}"
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

    def _b64_digest(data: bytes) -> str:
        return base64.b64encode(signer._hashlib(data).digest()).decode("ascii")

    if signer._private_key is not None and _padding is not None and _hashes is not None:
        for section_id, ref in ref_nodes.items():
            target = _find_by_id(combined, section_id)
            if target is None:
                raise EAddressSoapError(f"Missing signed section: {section_id}")
            hinted_digest = (
                (section_digest_hints.get(section_id) or "").strip()
                if section_digest_hints
                else ""
            )
            if hinted_digest:
                digest = hinted_digest
            else:
                # Java/official DIV client section digests resolve as exclusive C14N,
                # even though the emitted Reference transform advertises C14N 1.0.
                c14n = etree.tostring(target, method="c14n", exclusive=True, with_comments=False)
                digest = _b64_digest(c14n)
            dv = ref.find(f".//{{{zeep_ns.DS}}}DigestValue")
            if dv is not None:
                dv.text = digest

        sp_c14n = etree.tostring(
            signed_props,
            method="c14n",
            exclusive=True,
            with_comments=False,
            inclusive_ns_prefixes=["ds"],
        )
        sp_digest = _b64_digest(sp_c14n)
        sp_dv = ref_props.find(f".//{{{zeep_ns.DS}}}DigestValue")
        if sp_dv is not None:
            sp_dv.text = sp_digest

        # Java/Metro serializes long DigestValue nodes with line-wraps; keep the
        # same canonicalized SignedInfo text that DIV expects.
        for digest_node in signature.xpath(
            ".//ds:DigestValue", namespaces={"ds": zeep_ns.DS}
        ):
            if digest_node.text:
                digest_node.text = _wrap_digest_text(digest_node.text)

        _strip_whitespace_text_nodes(signature)
        signed_info = signature.find(f".//{{{zeep_ns.DS}}}SignedInfo")
        if signed_info is not None:
            si_c14n = etree.tostring(
                signed_info, method="c14n", exclusive=False, with_comments=False
            )
            sig_hash = signer._crypto_hash or _hashes.SHA512()
            sig_bytes = signer._private_key.sign(
                si_c14n, _padding.PKCS1v15(), sig_hash
            )
            sig_el = signature.find(f".//{{{zeep_ns.DS}}}SignatureValue")
            if sig_el is not None:
                sig_el.set("Id", signature_value_id)
                sig_el.text = base64.b64encode(sig_bytes).decode("ascii")
    else:
        ctx = xmlsec.SignatureContext()
        key = xmlsec.Key.from_file(str(signer.key_file), xmlsec.KeyFormat.PEM)
        key.load_cert_from_file(str(signer.cert_file), xmlsec.KeyFormat.PEM)
        ctx.key = key
        for section_id in signed_section_ids:
            target = _find_by_id(combined, section_id)
            if target is None:
                raise EAddressSoapError(f"Missing signed section: {section_id}")
            ctx.register_id(target, "Id")
        ctx.register_id(signed_props, "Id")
        _strip_whitespace_text_nodes(signature)
        ctx.sign(signature)
        sig_el = signature.find(f".//{{{zeep_ns.DS}}}SignatureValue")
        if sig_el is not None:
            sig_el.set("Id", signature_value_id)

    return deepcopy(signature)


def _resign_signature_value_in_context(
    signature: etree._Element,
    signer: SenderDocumentSigner,
) -> None:
    """Re-sign SignedInfo in its final namespace context."""
    if signer._private_key is None or _padding is None or _hashes is None:
        return
    root = signature.getroottree().getroot() if signature.getroottree() is not None else None
    if root is not None:
        refs = signature.xpath("./ds:SignedInfo/ds:Reference", namespaces={"ds": zeep_ns.DS})
        for ref in refs:
            uri = (ref.get("URI") or "").strip()
            if not uri.startswith("#"):
                continue
            target = _find_by_id(root, uri[1:])
            if target is None:
                continue
            ref_type = (ref.get("Type") or "").strip()
            inclusive_prefixes = ["ds"] if ref_type == "http://uri.etsi.org/01903#SignedProperties" else None
            c14n = etree.tostring(
                target,
                method="c14n",
                exclusive=True,
                with_comments=False,
                inclusive_ns_prefixes=inclusive_prefixes,
            )
            digest = _wrap_digest_text(base64.b64encode(signer._hashlib(c14n).digest()).decode("ascii"))
            digest_el = ref.find(f".//{{{zeep_ns.DS}}}DigestValue")
            if digest_el is not None:
                digest_el.text = digest
    _strip_whitespace_text_nodes(signature)
    signed_info = signature.find(f".//{{{zeep_ns.DS}}}SignedInfo")
    if signed_info is None:
        return
    si_c14n = etree.tostring(signed_info, method="c14n", exclusive=False, with_comments=False)
    sig_hash = signer._crypto_hash or _hashes.SHA512()
    sig_bytes = signer._private_key.sign(si_c14n, _padding.PKCS1v15(), sig_hash)
    sig_value = signature.find(f".//{{{zeep_ns.DS}}}SignatureValue")
    if sig_value is not None:
        sig_value.text = base64.b64encode(sig_bytes).decode("ascii")


def _safe_last_received(history) -> Optional[Mapping[str, etree._Element]]:
    if history is None:
        return None
    try:
        return history.last_received
    except Exception:
        return None


def _legacy_sign_confirmation_part(
    entry: etree._Element,
    signer: SenderDocumentSigner,
    signature_id: str,
    signed_props_suffix: str,
) -> etree._Element:
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
        signature, signer._digest_transform, uri=f"#{entry.get('Id')}"
    )
    xmlsec.template.add_transform(ref_recipient, xmlsec.Transform.C14N)

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

    ctx = xmlsec.SignatureContext()
    key = xmlsec.Key.from_file(str(signer.key_file), xmlsec.KeyFormat.PEM)
    key.load_cert_from_file(str(signer.cert_file), xmlsec.KeyFormat.PEM)
    ctx.key = key
    ctx.register_id(sign_entry, "Id")
    ctx.register_id(signed_props, "Id")
    ctx.sign(signature)
    return deepcopy(signature)

def confirm_message(
    token_provider: TokenProvider,
    soap_client: SoapClient,
    message_id: str,
    *,
    recipient_eaddresses: Optional[Iterable[str]] = None,
    message_envelope: Optional[etree._Element] = None,
    confirmation_name: Optional[str] = None,
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

    history = getattr(soap_client, "_history", None)
    last_received = _safe_last_received(history)
    if message_envelope is None and last_received:
        try:
            soap_env = last_received.get("envelope")
            if soap_env is not None:
                if QName(soap_env).namespace == DIV_NS and QName(soap_env).localname == "Envelope":
                    message_envelope = soap_env
                else:
                    message_envelope = soap_env.find(f".//{{{DIV_NS}}}Envelope")
        except Exception:
            message_envelope = None

    if recipient_eaddresses is None or message_envelope is None or confirmation_name is None:
        try:
            try:
                msg = svc.GetMessage(Token=token, MessageId=message_id)
            except TypeError:
                msg = svc.GetMessage(MessageId=message_id)
            data = serialize_object(msg) if msg is not None else {}
            confirmation_name = data.get("ConfirmationName") or confirmation_name
            if recipient_eaddresses is None:
                recipients = data.get("Recipients") or {}
                if isinstance(recipients, dict):
                    recipient_eaddresses = recipients.get("string", [])
            elif isinstance(recipients, list):
                recipient_eaddresses = recipients
            else:
                recipient_eaddresses = []
            last_received = _safe_last_received(history)
            if message_envelope is None and last_received:
                try:
                    soap_env = last_received.get("envelope")
                    if soap_env is not None:
                        message_envelope = soap_env.find(f".//{{{DIV_NS}}}Envelope")
                except Exception:
                    message_envelope = None
        except Exception:
            if recipient_eaddresses is None:
                recipient_eaddresses = []
    recipients = []
    for addr in recipient_eaddresses or []:
        value = str(addr).strip()
        if value:
            recipients.append(value)
    if not recipients:
        fallback = soap_client.cfg.default_from or ""
        if fallback:
            recipients = [fallback]

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
    for addr in recipients:
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

    signed_props_suffix = f"{uuid.uuid4().int % 100000000:08d}"

    if message_envelope is None:
        # Fallback for tests/stubs without a GetMessage XML envelope.
        signature = _legacy_sign_confirmation_part(
            entry, signer, signature_id, signed_props_suffix
        )
    else:
        section_digest_hints = _extract_section_digest_hints(message_envelope)
        combined = _combine_envelope_parts(
            "RecipientConfirmationPart",
            [message_envelope, part],
            include_existing_signatures=True,
        )
        combined = _netify_envelope(combined)
        signature = _sign_combined_envelope(
            combined,
            signer,
            signature_id,
            ["SenderSection", "ServerSection", entry_id],
            section_digest_hints=section_digest_hints,
        )

    signatures = etree.SubElement(part, QName(DIV_NS, "Signatures"))
    signatures.append(signature)

    action = "http://vraa.gov.lv/div/uui/2011/11/UnifiedServiceInterface/ConfirmMessage"
    use_direct_transport = getattr(soap_client, "_client", None) is not None

    if not use_direct_transport:
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
            raise EAddressSoapError(f"VUS ConfirmMessage call failed for {message_id}") from exc
        return True

    try:
        soap_env = "http://www.w3.org/2003/05/soap-envelope"
        uui_ns = "http://vraa.gov.lv/xmlschemas/div/uui/2011/11"
        envelope = etree.Element(
            QName(soap_env, "Envelope"),
            nsmap={"soap": soap_env, "wsa": zeep_ns.WSA, "wsse": zeep_ns.WSSE, "wsu": zeep_ns.WSU, None: uui_ns},
        )
        header = etree.SubElement(envelope, QName(soap_env, "Header"))
        action_el = etree.SubElement(header, QName(zeep_ns.WSA, "Action"))
        action_el.text = action
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

        # Match Java dispatchConfirmMessage: netify marshalled ConfirmMessageInput
        # right before dispatch.
        netified_input = _netify_envelope(confirm_input)
        if netified_input is not None and netified_input is not confirm_input:
            body.remove(confirm_input)
            confirm_input = deepcopy(netified_input)
            body.append(confirm_input)

        http_headers = {}
        if getattr(soap_client, "_wsse", None) is not None:
            envelope, http_headers = soap_client._wsse.apply(envelope, http_headers)

        debug_dir = (os.environ.get("EADRESE_DEBUG_DIR") or "").strip()
        if debug_dir:
            try:
                out_dir = Path(debug_dir)
                out_dir.mkdir(parents=True, exist_ok=True)
                safe_id = "".join(ch if ch.isalnum() else "_" for ch in str(message_id)) or "message"
                request_xml = etree.tostring(envelope, encoding="utf-8", xml_declaration=False)
                (out_dir / f"confirm_{safe_id}_request.xml").write_bytes(request_xml)
            except Exception:
                pass

        http_headers = dict(http_headers or {})
        http_headers.setdefault(
            "Content-Type",
            f'application/soap+xml; charset=utf-8; action="{action}"',
        )
        http_headers.setdefault("Accept", "application/soap+xml, text/xml")

        address = soap_client.cfg.wsdl_url.replace("?wsdl", "")
        response = soap_client._client.transport.post_xml(address, envelope, http_headers)

        status_code = getattr(response, "status_code", None)
        raw_content = getattr(response, "content", b"") or b""
        if debug_dir:
            try:
                out_dir = Path(debug_dir)
                safe_id = "".join(ch if ch.isalnum() else "_" for ch in str(message_id)) or "message"
                (out_dir / f"confirm_{safe_id}_response.raw").write_bytes(raw_content)
            except Exception:
                pass
        fault_reason = None
        if raw_content:
            try:
                root = etree.fromstring(raw_content)
                fault_nodes = root.xpath(".//*[local-name()='Fault']")
                if fault_nodes:
                    texts = fault_nodes[0].xpath(".//*[local-name()='Text']/text()")
                    reasons = [t.strip() for t in texts if isinstance(t, str) and t.strip()]
                    fault_reason = reasons[0] if reasons else "SOAP Fault"
            except Exception:
                fault_reason = None

        if status_code is not None and int(status_code) >= 400:
            detail = f": {fault_reason}" if fault_reason else ""
            raise EAddressSoapError(
                f"VUS ConfirmMessage fallback HTTP {status_code} for {message_id}{detail}"
            )
        if fault_reason:
            raise EAddressSoapError(f"VUS ConfirmMessage fallback fault for {message_id}: {fault_reason}")
        return True
    except Exception as raw_exc:
        raise EAddressSoapError(f"VUS ConfirmMessage call failed for {message_id}: {raw_exc}") from raw_exc
    return True
