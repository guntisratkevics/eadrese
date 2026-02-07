from typing import Any, List, Mapping
from zeep.helpers import serialize_object
from ..errors import EAddressSoapError
from ..auth import TokenProvider
from ..soap.client import SoapClient

def search_addressee(
    token_provider: TokenProvider,
    soap_client: SoapClient,
    registration_number: str
) -> List[Mapping[str, Any]]:
    """Search for an addressee by registration number."""
    token = token_provider.get_token() if token_provider else None
    svc = soap_client.service
    
    try:
        if hasattr(svc, "SearchAddresseeUnit"):
            if token:
                response = svc.SearchAddresseeUnit(Token=token, RegistrationNumber=registration_number)
            else:
                response = svc.SearchAddresseeUnit(RegistrationNumber=registration_number)
        else:
            raise EAddressSoapError("Service has no SearchAddresseeUnit method")
    except Exception as exc:
         raise EAddressSoapError(f"VUS SearchAddressee call failed for {registration_number}") from exc
    
    data = serialize_object(response)
    if not data:
        return []
        
    results = data.get("Addressee", [])
    if isinstance(results, dict):
        return [results]
    return results


def get_public_key_list(
    token_provider: TokenProvider,
    soap_client: SoapClient,
    recipients: List[str],
) -> List[Mapping[str, Any]]:
    """Fetch recipient public keys (modulus/exponent + thumbprint) for encryption."""
    token = token_provider.get_token() if token_provider else None
    svc = soap_client.service

    try:
        if hasattr(svc, "GetPublicKeyList"):
            payload = {"Recipients": {"string": recipients}}
            try:
                response = svc.GetPublicKeyList(Token=token, **payload) if token else svc.GetPublicKeyList(**payload)
            except TypeError:
                response = svc.GetPublicKeyList(Token=token, Recipients=recipients) if token else svc.GetPublicKeyList(Recipients=recipients)
        else:
            raise EAddressSoapError("Service has no GetPublicKeyList method")
    except Exception as exc:
        raise EAddressSoapError("VUS GetPublicKeyList call failed") from exc

    data = serialize_object(response)
    if not data:
        return []
    if isinstance(data, list):
        results = data
    else:
        results = data.get("PublicKeys") or data.get("RecipientPublicKey") or []
    if isinstance(results, dict):
        return [results]
    return results
