import logging
import datetime as _dt
import uuid
import requests
from zeep import Client, Settings, ns
from zeep.plugins import HistoryPlugin
from zeep.transports import Transport
from zeep.wsse.signature import Signature
from zeep.wsse.utils import get_security_header
from lxml import etree
from lxml.etree import QName
import xmlsec


class SignOnlySignature(Signature):
    """WSSE signature that optionally adds Timestamp and skips response verification."""

    def __init__(
        self,
        key_file,
        certfile,
        *,
        add_timestamp: bool = False,
        verify_response: bool = False,
        signature_method=None,
        digest_method=None,
    ):
        signature_method = signature_method or xmlsec.Transform.RSA_SHA256
        digest_method = digest_method or xmlsec.Transform.SHA256
        super().__init__(
            key_file,
            certfile,
            signature_method=signature_method,
            digest_method=digest_method,
        )
        self._add_timestamp = add_timestamp
        self._verify_response = verify_response

    def verify(self, envelope):
        if self._verify_response:
            return super().verify(envelope)
        return envelope

    def apply(self, envelope, headers):
        if self._add_timestamp:
            security = get_security_header(envelope)
            ts = QName(ns.WSU, "Timestamp")
            id_attr = {QName(ns.WSU, "Id"): f"TS-{uuid.uuid4()}"}
            ts_el = security.find(ts)
            if ts_el is None:
                ts_el = etree.SubElement(security, ts, id_attr)
            else:
                ts_el.clear()
                ts_el.attrib.update(id_attr)
            now = _dt.datetime.utcnow()
            created = (now).isoformat(timespec="seconds") + "Z"
            expires = (now + _dt.timedelta(minutes=5)).isoformat(timespec="seconds") + "Z"
            created_el = etree.SubElement(ts_el, QName(ns.WSU, "Created"))
            created_el.text = created
            expires_el = etree.SubElement(ts_el, QName(ns.WSU, "Expires"))
            expires_el.text = expires
        return super().apply(envelope, headers)
from ..config import EAddressConfig

logger = logging.getLogger(__name__)

class SoapClient:
    def __init__(self, cfg: EAddressConfig, session: requests.Session, service=None):
        self.cfg = cfg
        self._history = HistoryPlugin() if service is None else None
        
        if service is not None:
            self._client = None
            self.service = service
        else:
            transport = Transport(session=session, timeout=cfg.timeout)
            wsse = None
            if cfg.wsse_signing and cfg.certificate and cfg.private_key:
                # Signature expects key file first, certificate second
                wsse = SignOnlySignature(
                    str(cfg.private_key),
                    str(cfg.certificate),
                    add_timestamp=cfg.wsse_timestamp,
                    verify_response=cfg.wsse_verify,
                )

            settings = Settings(strict=False, xml_huge_tree=True)
            self._client = Client(
                cfg.wsdl_url,
                transport=transport,
                plugins=[self._history] if self._history else None,
                wsse=wsse,
                settings=settings,
            )
            # DIV test/prod bindings use the DIV namespace/binding name
            binding = "{http://vraa.gov.lv/div/uui/2011/11}UnifiedServiceHttpBinding_UnifiedServiceInterface"
            self.service = self._client.create_service(binding, cfg.wsdl_url.replace("?wsdl", ""))
        
        logger.info("Initialized e-adrese SOAP client @ %s", cfg.wsdl_url)

    def getattr(self, name):
        if hasattr(self.service, name):
            return getattr(self.service, name)
        # Fallback if service is a callable mock
        if callable(self.service): 
             return self.service 
        return None
