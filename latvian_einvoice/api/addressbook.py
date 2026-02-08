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
    """Search for an addressee by registration number / personal code."""
    token = token_provider.get_token() if token_provider else None
    svc = soap_client.service
    
    try:
        if hasattr(svc, "SearchAddresseeUnit"):
            # Primary: UnifiedServiceInterface schema (Owner.Code search)
            payload = {"AddresseeUnitOwner": {"Code": registration_number}}
            try:
                if token:
                    response = svc.SearchAddresseeUnit(Token=token, **payload)
                else:
                    response = svc.SearchAddresseeUnit(**payload)
            except TypeError:
                # Fallback: some stubs/older clients used RegistrationNumber
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

    # UnifiedServiceInterface returns AddresseeUnits/AddresseeUnit; keep backward-compat for Addressee.
    results = data.get("AddresseeUnits") or data.get("AddresseeUnit") or data.get("Addressee") or []
    if isinstance(results, dict):
        results = results.get("AddresseeUnit") or results.get("Addressee") or results
    if isinstance(results, dict):
        return [results]
    if isinstance(results, list):
        return [r for r in results if isinstance(r, dict)]
    return []


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
        results = results.get("RecipientPublicKey") or results
    if isinstance(results, dict):
        return [results]
    if isinstance(results, list):
        return [r for r in results if isinstance(r, dict)]
    return []
