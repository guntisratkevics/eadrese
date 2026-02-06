import logging
import base64
import datetime as _dt
from datetime import timezone
import uuid
import hashlib
import ssl
from pathlib import Path
import requests
from zeep import Client, Plugin, Settings, ns
from zeep.plugins import HistoryPlugin
from zeep.transports import Transport
from zeep.wsse.signature import Signature
from zeep.wsse.utils import ensure_id, get_security_header
from zeep.utils import detect_soap_env
from lxml import etree
from lxml.etree import QName
try:
    import xmlsec
except ImportError:  # pragma: no cover - optional dependency
    xmlsec = None
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
except ImportError:  # pragma: no cover - optional dependency
    x509 = None
    hashes = None
    serialization = None
    padding = None
    rsa = None

DIV_NS = "http://ivis.eps.gov.lv/XMLSchemas/100001/DIV/v1-0"

class SenderDocumentSigner(Plugin):
    """Zeep plugin that signs the SenderDocument section (envelope content)."""

    def __init__(
        self,
        key_file: str,
        cert_file: str,
        chain_file: str | None = None,
        sig_hash: str = "sha512",
    ):
        if xmlsec is None:
            raise ImportError("xmlsec is required for signing (install python-xmlsec)")
        self.key_file = key_file
        self.cert_file = cert_file
        self.chain_file = chain_file
        algo = (sig_hash or "sha512").lower()
        if algo == "sha256":
            self._sig_transform = xmlsec.Transform.RSA_SHA256
            self._digest_transform = xmlsec.Transform.SHA256
            self._digest_uri = "http://www.w3.org/2001/04/xmlenc#sha256"
            self._hashlib = hashlib.sha256
            self._crypto_hash = hashes.SHA256() if hashes is not None else None
        else:
            self._sig_transform = xmlsec.Transform.RSA_SHA512
            self._digest_transform = xmlsec.Transform.SHA512
            self._digest_uri = "http://www.w3.org/2001/04/xmlenc#sha512"
            self._hashlib = hashlib.sha512
            self._crypto_hash = hashes.SHA512() if hashes is not None else None
        cert_text = Path(cert_file).read_text()
        # Use first certificate in the bundle as the signing cert
        if "-----BEGIN CERTIFICATE-----" in cert_text:
            first_block = cert_text.split("-----BEGIN CERTIFICATE-----", 1)[1]
            first_pem = "-----BEGIN CERTIFICATE-----" + first_block.split(
                "-----END CERTIFICATE-----", 1
            )[0] + "-----END CERTIFICATE-----"
        else:
            first_pem = cert_text
        cert_der = ssl.PEM_cert_to_DER_cert(first_pem)
        self.cert_b64 = base64.b64encode(cert_der).decode("ascii")
        self.cert_sha1_b64 = base64.b64encode(hashlib.sha1(cert_der).digest()).decode("ascii")
        # Collect additional certs (chain) for KeyInfo
        self._extra_cert_b64 = []
        def _collect_pems(text):
            blocks = []
            if "-----BEGIN CERTIFICATE-----" not in text:
                return blocks
            parts = text.split("-----BEGIN CERTIFICATE-----")
            for part in parts[1:]:
                body, _sep, _rest = part.partition("-----END CERTIFICATE-----")
                blocks.append("-----BEGIN CERTIFICATE-----" + body + "-----END CERTIFICATE-----")
            return blocks
        # Any remaining certs in cert_file after the first
        for pem in _collect_pems(cert_text)[1:]:
            try:
                der = ssl.PEM_cert_to_DER_cert(pem)
                self._extra_cert_b64.append(base64.b64encode(der).decode("ascii"))
            except Exception:
                continue
        if chain_file:
            try:
                chain_text = Path(chain_file).read_text()
                for pem in _collect_pems(chain_text):
                    der = ssl.PEM_cert_to_DER_cert(pem)
                    b64 = base64.b64encode(der).decode("ascii")
                    if b64 != self.cert_b64 and b64 not in self._extra_cert_b64:
                        self._extra_cert_b64.append(b64)
            except Exception:
                pass
        decoded = ssl._ssl._test_decode_cert(cert_file)
        issuer_parts = []
        subject_parts = []
        key_map = {
            "commonName": "CN",
            "domainComponent": "DC",
            "organizationName": "O",
            "organizationalUnitName": "OU",
            "countryName": "C",
        }
        for rdn in reversed(decoded.get("subject", [])):
            for key, value in rdn:
                prefix = key_map.get(key, key)
                subject_parts.append(f"{prefix}={value}")
        for rdn in reversed(decoded.get("issuer", [])):
            for key, value in rdn:
                prefix = key_map.get(key, key)
                issuer_parts.append(f"{prefix}={value}")
        self.subject_name = ", ".join(subject_parts)
        self.issuer_name = ", ".join(issuer_parts)
        serial_raw = decoded.get("serialNumber")
        try:
            self.serial_number = str(int(str(serial_raw), 16))
        except Exception:
            self.serial_number = str(serial_raw)
        self.modulus_b64 = None
        self.exponent_b64 = None
        self._private_key = None
        if x509 is not None:
            try:
                cert_obj = x509.load_der_x509_certificate(cert_der)
                pub_key = cert_obj.public_key()
                if isinstance(pub_key, rsa.RSAPublicKey):
                    numbers = pub_key.public_numbers()
                    mod_len = max(1, (numbers.n.bit_length() + 7) // 8)
                    exp_len = max(1, (numbers.e.bit_length() + 7) // 8)
                    self.modulus_b64 = base64.b64encode(
                        numbers.n.to_bytes(mod_len, "big")
                    ).decode("ascii")
                    self.exponent_b64 = base64.b64encode(
                        numbers.e.to_bytes(exp_len, "big")
                    ).decode("ascii")
            except Exception:
                self.modulus_b64 = None
                self.exponent_b64 = None
        if serialization is not None:
            try:
                key_bytes = Path(key_file).read_bytes()
                self._private_key = serialization.load_pem_private_key(
                    key_bytes, password=None
                )
            except Exception:
                self._private_key = None

    def egress(self, envelope, http_headers, operation, binding_options):
        # Round-trip to freeze namespace declarations before inclusive C14N signing.
        try:
            envelope = etree.fromstring(etree.tostring(envelope))
        except Exception:
            pass
        soap_env = detect_soap_env(envelope)
        if not soap_env:
            return envelope, http_headers
        body = envelope.find(QName(soap_env, "Body"))
        if body is None:
            return envelope, http_headers
        # Normalize SendMessageInput to default namespace (match Java SOAP prefixing).
        op_node = next(iter(body), None)
        if op_node is not None and op_node.prefix is not None:
            op_qname = QName(op_node)
            parent = op_node.getparent()
            if parent is not None:
                new_op = etree.Element(QName(op_qname.namespace, op_qname.localname), nsmap={None: op_qname.namespace})
                for key, value in op_node.attrib.items():
                    new_op.set(key, value)
                for child in list(op_node):
                    new_op.append(child)
                parent.replace(op_node, new_op)
        env_node = body.find(f".//{{{DIV_NS}}}Envelope")
        if env_node is not None and env_node.prefix is not None:
            parent = env_node.getparent()
            if parent is not None:
                new_env = etree.Element(QName(DIV_NS, "Envelope"), nsmap={None: DIV_NS})
                for key, value in env_node.attrib.items():
                    new_env.set(key, value)
                for child in list(env_node):
                    new_env.append(child)
                parent.replace(env_node, new_env)
                env_node = new_env
        if env_node is None:
            return envelope, http_headers
        # Sign a standalone DIV Envelope copy so SignedInfo doesn't inherit SOAP namespaces.
        env_for_sign = etree.fromstring(etree.tostring(env_node))
        etree.cleanup_namespaces(env_for_sign)
        sender_doc = env_for_sign.find(f".//{{{DIV_NS}}}SenderDocument")
        signatures = env_for_sign.find(f".//{{{DIV_NS}}}Signatures")
        if sender_doc is None or signatures is None:
            return envelope, http_headers
        # Clear any placeholder signatures
        for child in list(signatures):
            signatures.remove(child)

        signature_id = "SenderSignature"
        signature = xmlsec.template.create(
            env_for_sign,
            xmlsec.Transform.C14N,
            self._sig_transform,
            ns="ds",
        )
        ref = xmlsec.template.add_reference(
            signature, self._digest_transform, uri=f"#{sender_doc.get('Id')}"
        )
        # Java sidecar digest aligns with exclusive C14N for SenderDocument.
        xmlsec.template.add_transform(ref, xmlsec.Transform.EXCL_C14N)
        signed_props_suffix = f"{uuid.uuid4().int % 100000000:08d}"
        signed_props_id = f"ds-SignedProperties-{signed_props_suffix}"
        signed_props_tag = f"SignedProperties-{signed_props_suffix}"
        signature_value_id = f"ds-SignatureValue-{signed_props_suffix}"
        ref_props = xmlsec.template.add_reference(
            signature, self._digest_transform, uri=f"#{signed_props_id}"
        )
        ref_props.set("Type", "http://uri.etsi.org/01903#SignedProperties")

        key_info = xmlsec.template.ensure_key_info(signature)
        key_info.set("Id", "ds-KeyInfo")
        if self.modulus_b64 and self.exponent_b64:
            key_value = etree.SubElement(key_info, QName(ns.DS, "KeyValue"))
            rsa_key_value = etree.SubElement(key_value, QName(ns.DS, "RSAKeyValue"))
            etree.SubElement(rsa_key_value, QName(ns.DS, "Modulus")).text = self.modulus_b64
            etree.SubElement(rsa_key_value, QName(ns.DS, "Exponent")).text = self.exponent_b64
        x509_data = etree.SubElement(key_info, QName(ns.DS, "X509Data"))
        etree.SubElement(x509_data, QName(ns.DS, "X509Certificate")).text = self.cert_b64
        if self.subject_name:
            etree.SubElement(x509_data, QName(ns.DS, "X509SubjectName")).text = self.subject_name
        if self.issuer_name and self.serial_number:
            issuer_serial = etree.SubElement(x509_data, QName(ns.DS, "X509IssuerSerial"))
            etree.SubElement(
                issuer_serial, QName(ns.DS, "X509IssuerName")
            ).text = self.issuer_name
            etree.SubElement(
                issuer_serial, QName(ns.DS, "X509SerialNumber")
            ).text = self.serial_number
        signature.set("Id", signature_id)

        xades_ns = "http://uri.etsi.org/01903/v1.3.2#"
        qp = etree.Element(
            QName(xades_ns, "QualifyingProperties"),
            nsmap={None: xades_ns},
        )
        qp.set("Target", f"#{signature_id}")
        qp.set("Id", "ds-QualifyingProperties")
        signed_props = etree.SubElement(
            qp,
            QName(xades_ns, signed_props_tag),
        )
        signed_props.set("Id", signed_props_id)
        ssp = etree.SubElement(signed_props, QName(xades_ns, "SignedSignatureProperties"))
        signing_time = etree.SubElement(ssp, QName(xades_ns, "SigningTime"))
        signing_time.text = _dt.datetime.now().astimezone().isoformat(timespec="seconds")
        sc = etree.SubElement(ssp, QName(xades_ns, "SigningCertificate"))
        cert_el = etree.SubElement(sc, QName(xades_ns, "Cert"))
        cert_digest = etree.SubElement(cert_el, QName(xades_ns, "CertDigest"))
        etree.SubElement(
            cert_digest,
            QName(ns.DS, "DigestMethod"),
            Algorithm="http://www.w3.org/2000/09/xmldsig#sha1",
        )
        etree.SubElement(cert_digest, QName(ns.DS, "DigestValue")).text = self.cert_sha1_b64
        issuer_serial = etree.SubElement(cert_el, QName(xades_ns, "IssuerSerial"))
        etree.SubElement(issuer_serial, QName(ns.DS, "X509IssuerName")).text = self.issuer_name
        etree.SubElement(issuer_serial, QName(ns.DS, "X509SerialNumber")).text = self.serial_number
        obj = etree.SubElement(signature, QName(ns.DS, "Object"))
        obj.append(qp)
        signatures.append(signature)

        def _strip_blank_text(node):
            for el in node.iter():
                if el.text is not None and el.text.strip() == "":
                    el.text = None
                if el.tail is not None and el.tail.strip() == "":
                    el.tail = None

        _strip_blank_text(signature)

        # No transforms for SignedProperties reference (match Java sidecar output).

        def _b64_digest(data: bytes) -> str:
            return base64.b64encode(self._hashlib(data).digest()).decode("ascii")

        if self._private_key is not None and hashes is not None and padding is not None:
            sender_c14n = etree.tostring(
                sender_doc, method="c14n", exclusive=True, with_comments=False
            )
            sender_digest = _b64_digest(sender_c14n)
            sender_dv = ref.find(f".//{{{ns.DS}}}DigestValue")
            if sender_dv is not None:
                sender_dv.text = sender_digest

            sp_c14n = etree.tostring(
                signed_props,
                method="c14n",
                exclusive=True,
                with_comments=False,
                inclusive_ns_prefixes=["ds"],
            )
            sp_digest = _b64_digest(sp_c14n)
            sp_dv = ref_props.find(f".//{{{ns.DS}}}DigestValue")
            if sp_dv is not None:
                sp_dv.text = sp_digest

            signed_info = signature.find(f".//{{{ns.DS}}}SignedInfo")
            if signed_info is not None:
                si_c14n = etree.tostring(
                    signed_info, method="c14n", exclusive=False, with_comments=False
                )
                self._last_si_c14n = si_c14n
                self._last_si_hash = base64.b64encode(
                    hashlib.sha512(si_c14n).digest()
                ).decode("ascii")
                sig_hash = self._crypto_hash or hashes.SHA512()
                sig_bytes = self._private_key.sign(
                    si_c14n, padding.PKCS1v15(), sig_hash
                )
                sig_el = signature.find(f".//{{{ns.DS}}}SignatureValue")
                if sig_el is not None:
                    sig_el.set("Id", signature_value_id)
                    sig_el.text = base64.b64encode(sig_bytes).decode("ascii")
        else:
            ctx = xmlsec.SignatureContext()
            key = xmlsec.Key.from_file(self.key_file, xmlsec.KeyFormat.PEM)
            key.load_cert_from_file(self.cert_file, xmlsec.KeyFormat.PEM)
            ctx.key = key
            ctx.register_id(sender_doc, "Id")
            ctx.register_id(signed_props, "Id")
            ctx.sign(signature)
            sig_el = signature.find(f".//{{{ns.DS}}}SignatureValue")
            if sig_el is not None:
                sig_el.set("Id", signature_value_id)
        # Replace original DIV Envelope with the signed, standalone copy.
        parent = env_node.getparent()
        if parent is not None:
            parent.replace(env_node, env_for_sign)
        return envelope, http_headers


class SignOnlySignature(Signature):
    """WSSE signature (asymmetric) with optional Timestamp and optional response verification."""

    def __init__(
        self,
        key_file,
        certfile,
        *,
        add_timestamp: bool = False,
        verify_response: bool = False,
        trust_store_path: str | None = None,
        response_cert_path: str | None = None,
        sender_sig_hash: str = "sha512",
        signature_method=None,
        digest_method=None,
    ):
        if xmlsec is None:
            raise ImportError("xmlsec is required for WS-Security signatures (install python-xmlsec)")
        # Match Metro/Java: RSA-SHA1/SHA1 for WS-Security signature
        signature_method = signature_method or xmlsec.Transform.RSA_SHA1
        digest_method = digest_method or xmlsec.Transform.SHA1
        super().__init__(
            key_file,
            certfile,
            signature_method=signature_method,
            digest_method=digest_method,
        )
        self.key_file = key_file
        self.certfile = certfile
        self._signature_method = signature_method
        self._digest_method = digest_method
        self._trust_store_path = trust_store_path
        self._response_cert_path = response_cert_path
        with open(certfile, "rb") as fh:
            cert_bytes = fh.read()
            self._cert_b64 = base64.b64encode(cert_bytes).decode("ascii").replace("\n", "")
            self._cert_sha1_b64 = base64.b64encode(hashlib.sha1(cert_bytes).digest()).decode("ascii")
            decoded = ssl._ssl._test_decode_cert(certfile)
            issuer_parts = []
            key_map = {
                "commonName": "CN",
                "domainComponent": "DC",
                "organizationName": "O",
                "organizationalUnitName": "OU",
                "countryName": "C",
            }
            for rdn in reversed(decoded.get("issuer", [])):
                for key, value in rdn:
                    prefix = key_map.get(key, key)
                    issuer_parts.append(f"{prefix}={value}")
            self._issuer_name = ", ".join(issuer_parts)
            serial_raw = decoded.get("serialNumber")
            try:
                self._serial_number = str(int(str(serial_raw), 16))
            except Exception:
                self._serial_number = str(serial_raw)
        self._add_timestamp = add_timestamp
        self._verify_response = verify_response
        self._sender_doc_signer = SenderDocumentSigner(
            self.key_file,
            self.certfile,
            self._trust_store_path,
            sender_sig_hash,
        )

    def verify(self, envelope):
        if not self._verify_response:
            return envelope
        # Verify the first Signature found in the envelope using the trust store
        sign_node = envelope.find(".//{http://www.w3.org/2000/09/xmldsig#}Signature")
        if sign_node is None:
            return envelope
        if self._response_cert_path:
            ctx = xmlsec.SignatureContext()
            fmt_cert = getattr(xmlsec.constants, "KeyDataFormatCertPem", xmlsec.constants.KeyDataFormatPem)
            ctx.key = xmlsec.Key.from_file(self._response_cert_path, fmt_cert)
            ctx.verify(sign_node)
        elif self._trust_store_path:
            manager = xmlsec.KeysManager()
            manager.load_cert(
                self._trust_store_path,
                xmlsec.constants.KeyDataFormatPem,
                xmlsec.constants.KeyDataTypeTrusted,
            )
            ctx = xmlsec.SignatureContext(manager)
            ctx.verify(sign_node)

        # Optional OCSP validation (best-effort)
        if getattr(self, "_verify_response_ocsp", False):
            try:
                from cryptography import x509
                leaf_pem = Path(self._trust_store_path).read_bytes()
                leaf = x509.load_pem_x509_certificate(leaf_pem)
                # simplistic: single cert trust store, attempt OCSP
                if not validate_chain_with_ocsp(leaf_pem, [leaf_pem]):
                    raise xmlsec.Error("OCSP validation failed")
            except Exception as exc:
                raise
        return envelope

    def apply(self, envelope, headers):
        security = get_security_header(envelope)
        soap_env = detect_soap_env(envelope)
        if soap_env:
            security.set(QName(soap_env, "mustUnderstand"), "true")
        body = envelope.find(QName(soap_env, "Body")) if soap_env else None
        for existing in list(security.findall(QName(ns.DS, "Signature"))):
            security.remove(existing)

        timestamp_el = None
        if self._add_timestamp:
            timestamp_el = security.find(QName(ns.WSU, "Timestamp"))
            if timestamp_el is None:
                timestamp_el = etree.SubElement(security, QName(ns.WSU, "Timestamp"))
            else:
                for child in list(timestamp_el):
                    timestamp_el.remove(child)
            ensure_id(timestamp_el)
            now = _dt.datetime.now(timezone.utc)
            created = (now).isoformat(timespec="seconds").replace("+00:00", "Z")
            expires = (now + _dt.timedelta(minutes=5)).isoformat(timespec="seconds").replace("+00:00", "Z")
            created_el = etree.SubElement(timestamp_el, QName(ns.WSU, "Created"))
            created_el.text = created
            expires_el = etree.SubElement(timestamp_el, QName(ns.WSU, "Expires"))
            expires_el.text = expires

        header = envelope.find(QName(soap_env, "Header")) if soap_env else None
        if header is None:
            header = etree.SubElement(envelope, QName(soap_env, "Header"))

        to_el = header.find(f".//{{{ns.WSA}}}To")
        if to_el is None:
            to_el = etree.SubElement(header, QName(ns.WSA, "To"))
        to_el.text = "https://divtest.vraa.gov.lv/Vraa.Div.WebService.UnifiedInterface/UnifiedService.svc"
        ensure_id(to_el)

        action_el = header.find(f".//{{{ns.WSA}}}Action")
        if action_el is None:
            action_el = etree.SubElement(header, QName(ns.WSA, "Action"))
            action_el.text = "http://vraa.gov.lv/div/uui/2011/11/UnifiedServiceInterface/SendMessage"
        # Metro sets mustUnderstand=true on Action
        action_el.set(QName(soap_env, "mustUnderstand"), "true")

        reply_to_el = header.find(f".//{{{ns.WSA}}}ReplyTo")
        if reply_to_el is None:
            reply_to_el = etree.SubElement(header, QName(ns.WSA, "ReplyTo"))
            addr_el = etree.SubElement(reply_to_el, QName(ns.WSA, "Address"))
            addr_el.text = "http://www.w3.org/2005/08/addressing/anonymous"

        fault_to_el = header.find(f".//{{{ns.WSA}}}FaultTo")
        if fault_to_el is None:
            fault_to_el = etree.SubElement(header, QName(ns.WSA, "FaultTo"))
            addr_el = etree.SubElement(fault_to_el, QName(ns.WSA, "Address"))
            addr_el.text = "http://www.w3.org/2005/08/addressing/anonymous"

        msg_id_el = header.find(f".//{{{ns.WSA}}}MessageID")
        if msg_id_el is None:
            msg_id_el = etree.SubElement(header, QName(ns.WSA, "MessageID"))
            msg_id_el.text = f"uuid:{uuid.uuid4()}"
        else:
            text = (msg_id_el.text or "").strip()
            if text.startswith("urn:uuid:"):
                msg_id_el.text = "uuid:" + text.split("urn:uuid:", 1)[1]

        bst_id = f"BST-{uuid.uuid4()}"
        bst = etree.Element(
            QName(ns.WSSE, "BinarySecurityToken"),
            {
                QName(ns.WSU, "Id"): bst_id,
                "ValueType": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3",
                "EncodingType": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary",
            },
        )
        bst.text = self._cert_b64
        insert_at = 0
        if timestamp_el is not None:
            insert_at = list(security).index(timestamp_el) + 1
        security.insert(insert_at, bst)

        signature = xmlsec.template.create(
            envelope,
            xmlsec.Transform.EXCL_C14N,
            self._signature_method,
        )
        key_info = xmlsec.template.ensure_key_info(signature)
        # Metro uses STR Reference to BST (no thumbprint)
        str_el = etree.SubElement(key_info, QName(ns.WSSE, "SecurityTokenReference"))
        etree.SubElement(
            str_el,
            QName(ns.WSSE, "Reference"),
            {
                "URI": f"#{bst_id}",
                "ValueType": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3",
            },
        )
        security.append(signature)

        ctx = xmlsec.SignatureContext()
        key = xmlsec.Key.from_file(self.key_file, xmlsec.KeyFormat.PEM)
        key.load_cert_from_file(self.certfile, xmlsec.KeyFormat.PEM)
        ctx.key = key

        def _add_inclusive(node, prefixes):
            if not prefixes:
                return
            inc = etree.SubElement(
                node,
                QName("http://www.w3.org/2001/10/xml-exc-c14n#", "InclusiveNamespaces"),
            )
            inc.set("PrefixList", " ".join(prefixes))

        def _prefix_for(uri, node):
            for prefix, ns_uri in (node.nsmap or {}).items():
                if ns_uri == uri and prefix:
                    return prefix
            return None

        soap_prefix = _prefix_for(soap_env, envelope) if soap_env else None
        wsse_prefix = _prefix_for(ns.WSSE, security)
        wsu_prefix = _prefix_for(ns.WSU, timestamp_el) if timestamp_el is not None else None

        def _add_reference(target, prefixes=None):
            node_id = ensure_id(target)
            ctx.register_id(target, "Id", ns.WSU)
            ref = xmlsec.template.add_reference(
                signature, self._digest_method, uri="#" + node_id
            )
            transform = xmlsec.template.add_transform(ref, xmlsec.Transform.EXCL_C14N)
            _add_inclusive(transform, prefixes or [])

        # Add inclusive namespaces on canonicalization (wsse + soap)
        canon = signature.find(f".//{{{ns.DS}}}CanonicalizationMethod")
        _add_inclusive(
            canon,
            [p for p in (wsse_prefix, soap_prefix) if p],
        )

        if timestamp_el is not None:
            _add_reference(
                timestamp_el,
                [p for p in (wsu_prefix, wsse_prefix, soap_prefix) if p],
            )
        # DIV policy SignedParts includes To; keep signature minimal (Timestamp + To)
        if to_el is not None:
            _add_reference(to_el, [p for p in (soap_prefix,) if p])

        ctx.sign(signature)
        # Sign SenderDocument after WSSE is applied to avoid namespace drift
        if self._sender_doc_signer:
            envelope, headers = self._sender_doc_signer.egress(
                envelope, headers, None, None
            )
            self._sender_doc_si_hash = getattr(self._sender_doc_signer, "_last_si_hash", None)
            self._sender_doc_si_c14n = getattr(self._sender_doc_signer, "_last_si_c14n", None)
        # Capture final envelope after WSSE + SenderDocument signing for debug
        self._last_envelope = envelope
        return envelope, headers
from ..config import EAddressConfig

logger = logging.getLogger(__name__)

class SoapClient:
    def __init__(self, cfg: EAddressConfig, session: requests.Session, service=None):
        self.cfg = cfg
        self._history = HistoryPlugin() if service is None else None
        self._wsse = None
        
        if service is not None:
            self._client = None
            self.service = service
        else:
            transport = Transport(session=session, timeout=cfg.timeout)
            # mTLS support if cert/key provided
            if cfg.client_cert_path and cfg.client_key_path:
                session.cert = (str(cfg.client_cert_path), str(cfg.client_key_path))
            wsse = None
            if cfg.wsse_signing and cfg.certificate and cfg.private_key:
                # Signature expects key file first, certificate second
                wsse = SignOnlySignature(
                    str(cfg.private_key),
                    str(cfg.certificate),
                    add_timestamp=cfg.wsse_timestamp,
                    verify_response=cfg.wsse_verify,
                    trust_store_path=str(cfg.trust_store_path) if cfg.trust_store_path else None,
                    response_cert_path=str(cfg.response_cert_path) if cfg.response_cert_path else None,
                    sender_sig_hash=cfg.sender_sig_hash,
                )
            self._wsse = wsse

            settings = Settings(strict=False, xml_huge_tree=True)
            plugins = []
            if self._history:
                plugins.append(self._history)

            wsdl_url = cfg.local_wsdl_url or cfg.wsdl_url
            self._client = Client(
                wsdl_url,
                transport=transport,
                plugins=plugins or None,
                wsse=wsse,
                settings=settings,
            )
            # DIV test/prod bindings use the DIV namespace/binding name
            binding = "{http://vraa.gov.lv/div/uui/2011/11}UnifiedServiceHttpBinding_UnifiedServiceInterface"
            self.service = self._client.create_service(binding, wsdl_url.replace("?wsdl", ""))
        
        logger.info("Initialized e-adrese SOAP client @ %s", cfg.wsdl_url)

    def getattr(self, name):
        if hasattr(self.service, name):
            return getattr(self.service, name)
        # Fallback if service is a callable mock
        if callable(self.service): 
             return self.service 
        return None
