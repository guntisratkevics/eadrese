from typing import Any, List, Mapping
from zeep.helpers import serialize_object
from ..errors import EAddressSoapError
from ..auth import TokenProvider
from ..soap.client import SoapClient


def _root_error_text(exc: Exception) -> str:
    current = exc
    seen = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        next_exc = getattr(current, "__cause__", None) or getattr(current, "__context__", None)
        if next_exc is None:
            break
        current = next_exc
    text = str(current or exc).strip()
    if not text:
        text = str(exc).strip()
    return text


def _normalize_owner_code(value: str) -> str:
    text = (value or "").strip()
    digits = "".join(ch for ch in text if ch.isdigit())
    return digits or text


def _is_eaddress(value: str) -> bool:
    text = (value or "").strip()
    return bool(text and "@" in text and " " not in text)


def _call_search_addressee_unit(service, token: str | None, payload: Mapping[str, Any]):
    """Try with Token kwarg first (legacy bindings), then without (current DIV binding)."""
    if token:
        try:
            return service.SearchAddresseeUnit(Token=token, **payload)
        except TypeError:
            pass
    return service.SearchAddresseeUnit(**payload)


def search_addressee(
    token_provider: TokenProvider,
    soap_client: SoapClient,
    registration_number: str
) -> List[Mapping[str, Any]]:
    """Search for an addressee by registration number / personal code."""
    token = token_provider.get_token() if token_provider else None
    svc = soap_client.service
    
    try:
        if not hasattr(svc, "SearchAddresseeUnit"):
            raise EAddressSoapError("Service has no SearchAddresseeUnit method")

        query = (registration_number or "").strip()
        owner_code = _normalize_owner_code(query)
        attempts = []
        if _is_eaddress(query):
            attempts.append({"EAddress": query})
        else:
            if owner_code:
                attempts.append({"AddresseeOwnerCode": owner_code})
            if query and query != owner_code:
                attempts.append({"AddresseeOwnerCode": query})
            # Legacy fallback for older stubs/bindings.
            if owner_code:
                attempts.append({"AddresseeUnitOwner": {"Code": owner_code}})

        last_type_error = None
        response = None
        for payload in attempts:
            try:
                response = _call_search_addressee_unit(svc, token, payload)
                break
            except TypeError as exc:
                last_type_error = exc
                continue
            except Exception:
                # Business/authorization faults should not be masked by fallback payloads.
                raise

        if response is None:
            if last_type_error is not None:
                raise last_type_error
            raise EAddressSoapError("SearchAddresseeUnit call did not accept any known payload variant")
    except Exception as exc:
         detail = _root_error_text(exc)
         if detail:
             raise EAddressSoapError(
                 f"VUS SearchAddressee call failed for {registration_number}: {detail}"
             ) from exc
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
