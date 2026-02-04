import logging
import base64
import datetime as _dt
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
import xmlsec

DIV_NS = "http://ivis.eps.gov.lv/XMLSchemas/100001/DIV/v1-0"

class SenderDocumentSigner(Plugin):
    """Zeep plugin that signs the SenderDocument section (envelope content)."""

    def __init__(self, key_file: str, cert_file: str):
        self.key_file = key_file
        self.cert_file = cert_file
        cert_text = Path(cert_file).read_text()
        # Use first certificate in the bundle
        if "-----BEGIN CERTIFICATE-----" in cert_text:
            first_block = cert_text.split("-----BEGIN CERTIFICATE-----", 1)[1]
            first_pem = "-----BEGIN CERTIFICATE-----" + first_block.split(
                "-----END CERTIFICATE-----", 1
            )[0] + "-----END CERTIFICATE-----"
        else:
            first_pem = cert_text
        cert_der = ssl.PEM_cert_to_DER_cert(first_pem)
        self.cert_sha1_b64 = base64.b64encode(hashlib.sha1(cert_der).digest()).decode("ascii")
        decoded = ssl._ssl._test_decode_cert(cert_file)
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
        self.issuer_name = ", ".join(issuer_parts)
        serial_raw = decoded.get("serialNumber")
        try:
            self.serial_number = str(int(str(serial_raw), 16))
        except Exception:
            self.serial_number = str(serial_raw)

    def egress(self, envelope, http_headers, operation, binding_options):
        soap_env = detect_soap_env(envelope)
        if not soap_env:
            return envelope, http_headers
        body = envelope.find(QName(soap_env, "Body"))
        if body is None:
            return envelope, http_headers
        sender_doc = body.find(f".//{{{DIV_NS}}}SenderDocument")
        signatures = body.find(f".//{{{DIV_NS}}}Signatures")
        if sender_doc is None or signatures is None:
            return envelope, http_headers
        # Clear any placeholder signatures
        for child in list(signatures):
            signatures.remove(child)

        signature_id = "SenderSignature"
        signature = xmlsec.template.create(
            envelope,
            xmlsec.Transform.EXCL_C14N,
            xmlsec.Transform.RSA_SHA512,
        )
        ref = xmlsec.template.add_reference(
            signature, xmlsec.Transform.SHA512, uri=f"#{sender_doc.get('Id')}"
        )
        xmlsec.template.add_transform(ref, xmlsec.Transform.C14N)
        signed_props_id = "SignedProperties"
        ref_props = xmlsec.template.add_reference(
            signature, xmlsec.Transform.SHA512, uri=f"#{signed_props_id}"
        )
        ref_props.set("Type", "http://uri.etsi.org/01903#SignedProperties")

        key_info = xmlsec.template.ensure_key_info(signature)
        xmlsec.template.add_key_value(key_info)
        x509_data = xmlsec.template.add_x509_data(key_info)
        xmlsec.template.x509_data_add_certificate(x509_data)
        signature.set("Id", signature_id)

        xades_ns = "http://uri.etsi.org/01903/v1.3.2#"
        qp = etree.Element(QName(xades_ns, "QualifyingProperties"), nsmap={"xades": xades_ns})
        qp.set("Target", f"#{signature_id}")
        qp.set("Id", "QualifyingProperties")
        signed_props = etree.SubElement(qp, QName(xades_ns, "SignedProperties"))
        signed_props.set("Id", signed_props_id)
        ssp = etree.SubElement(signed_props, QName(xades_ns, "SignedSignatureProperties"))
        signing_time = etree.SubElement(ssp, QName(xades_ns, "SigningTime"))
        signing_time.text = _dt.datetime.utcnow().isoformat(timespec="seconds") + "Z"
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

        ctx = xmlsec.SignatureContext()
        key = xmlsec.Key.from_file(self.key_file, xmlsec.KeyFormat.PEM)
        key.load_cert_from_file(self.cert_file, xmlsec.KeyFormat.PEM)
        ctx.key = key
        ctx.register_id(sender_doc, "Id")
        ctx.register_id(signed_props, "Id")
        ctx.sign(signature)
        return envelope, http_headers


class SignOnlySignature(Signature):
    """WSSE signature that optionally adds Timestamp and skips response verification."""

    def __init__(
        self,
        key_file,
        certfile,
        *,
        add_timestamp: bool = False,
        verify_response: bool = False,
        trust_store_path: str | None = None,
        signature_method=None,
        digest_method=None,
    ):
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

    def verify(self, envelope):
        if not self._verify_response or not self._trust_store_path:
            return envelope
        # Verify the first Signature found in the envelope using the trust store
        sign_node = envelope.find(".//{http://www.w3.org/2000/09/xmldsig#}Signature")
        if sign_node is None:
            return envelope
        manager = xmlsec.KeysManager()
        manager.load_cert(self._trust_store_path, xmlsec.KeyDataFormatPem, xmlsec.KeyDataTypeTrusted)
        ctx = xmlsec.SignatureContext(manager)
        ctx.verify(sign_node)
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
            now = _dt.datetime.utcnow()
            created = (now).isoformat(timespec="seconds") + "Z"
            expires = (now + _dt.timedelta(minutes=5)).isoformat(timespec="seconds") + "Z"
            created_el = etree.SubElement(timestamp_el, QName(ns.WSU, "Created"))
            created_el.text = created
            expires_el = etree.SubElement(timestamp_el, QName(ns.WSU, "Expires"))
            expires_el.text = expires

        to_el = envelope.find(f".//{{{ns.WSA}}}To")
        if to_el is not None:
            ensure_id(to_el)
        else:
            # Inject minimal WS-Addressing headers if missing
            header = envelope.find(QName(soap_env, "Header")) if soap_env else None
            if header is None:
                header = etree.SubElement(envelope, QName(soap_env, "Header"))
            to_el = etree.SubElement(header, QName(ns.WSA, "To"))
            to_el.text = "http://vraa.gov.lv/div/uui/2011/11/UnifiedService"
            ensure_id(to_el)
            msg_id_el = etree.SubElement(header, QName(ns.WSA, "MessageID"))
            msg_id_el.text = f"urn:uuid:{uuid.uuid4()}"
            action_el = etree.SubElement(header, QName(ns.WSA, "Action"))
            action_el.text = "http://vraa.gov.lv/div/uui/2011/11/IUnifiedService/SendMessage"

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

        # XAdES SignedProperties (minimal BES)
        xades_ns = "http://uri.etsi.org/01903/v1.3.2#"
        qp = etree.Element(QName(xades_ns, "QualifyingProperties"), nsmap={"xades": xades_ns})
        qp.set("Target", f"#{ensure_id(signature)}")
        signed_props = etree.SubElement(qp, QName(xades_ns, "SignedProperties"))
        ensure_id(signed_props)
        ssp = etree.SubElement(signed_props, QName(xades_ns, "SignedSignatureProperties"))
        signing_time = etree.SubElement(ssp, QName(xades_ns, "SigningTime"))
        signing_time.text = _dt.datetime.utcnow().isoformat(timespec="seconds") + "Z"
        sc = etree.SubElement(ssp, QName(xades_ns, "SigningCertificate"))
        cert_el = etree.SubElement(sc, QName(xades_ns, "Cert"))
        cert_digest = etree.SubElement(cert_el, QName(xades_ns, "CertDigest"))
        etree.SubElement(cert_digest, QName(ns.DS, "DigestMethod"), Algorithm="http://www.w3.org/2000/09/xmldsig#sha1")
        etree.SubElement(cert_digest, QName(ns.DS, "DigestValue")).text = self._cert_sha1_b64
        issuer_serial = etree.SubElement(cert_el, QName(xades_ns, "IssuerSerial"))
        etree.SubElement(issuer_serial, QName(ns.DS, "X509IssuerName")).text = getattr(self, "_issuer_name", "")
        etree.SubElement(issuer_serial, QName(ns.DS, "X509SerialNumber")).text = getattr(self, "_serial_number", "")
        obj = etree.SubElement(signature, QName(ns.DS, "Object"))
        obj.append(qp)

        ctx = xmlsec.SignatureContext()
        key = xmlsec.Key.from_file(self.key_file, xmlsec.KeyFormat.PEM)
        key.load_cert_from_file(self.certfile, xmlsec.KeyFormat.PEM)
        ctx.key = key

        def _add_reference(target):
            node_id = ensure_id(target)
            ctx.register_id(target, "Id", ns.WSU)
            ref = xmlsec.template.add_reference(
                signature, self._digest_method, uri="#" + node_id
            )
            xmlsec.template.add_transform(ref, xmlsec.Transform.EXCL_C14N)

        if timestamp_el is not None:
            _add_reference(timestamp_el)
        if to_el is not None:
            _add_reference(to_el)
        if action_el is not None:
            _add_reference(action_el)
        if msg_id_el is not None:
            _add_reference(msg_id_el)
        if body is not None:
            _add_reference(body)
        # SignedProperties reference
        ref_props = xmlsec.template.add_reference(
            signature, self._digest_method, uri="#" + ensure_id(signed_props)
        )
        ref_props.set("Type", "http://uri.etsi.org/01903#SignedProperties")
        xmlsec.template.add_transform(ref_props, xmlsec.Transform.EXCL_C14N)

        ctx.sign(signature)
        return envelope, headers
from ..config import EAddressConfig

logger = logging.getLogger(__name__)

class SoapClient:
    def __init__(self, cfg: EAddressConfig, session: requests.Session, service=None):
        self.cfg = cfg
        self._history = HistoryPlugin() if service is None else None
        self._signer = (
            SenderDocumentSigner(str(cfg.private_key), str(cfg.certificate))
            if cfg.wsse_signing and cfg.certificate and cfg.private_key
            else None
        )
        
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
                )

            settings = Settings(strict=False, xml_huge_tree=True)
            plugins = []
            if self._history:
                plugins.append(self._history)
            if self._signer:
                plugins.append(self._signer)

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
