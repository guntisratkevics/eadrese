import logging
import requests
from zeep import Client, Settings
from zeep.plugins import HistoryPlugin
from zeep.transports import Transport
from zeep.wsse.signature import Signature
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
            if cfg.certificate and cfg.private_key:
                wsse = Signature(str(cfg.certificate), str(cfg.private_key))

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
