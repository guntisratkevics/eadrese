from typing import Any, List, Mapping, Optional

from zeep.helpers import serialize_object

from ..auth import TokenProvider
from ..errors import EAddressSoapError
from ..soap.client import SoapClient
from ._soap_utils import soap_call


def _root_error_text(exc: Exception) -> str:
    current = exc
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        next_exc = getattr(current, "__cause__", None) or getattr(current, "__context__", None)
        if next_exc is None:
            break
        current = next_exc
    text = str(current or exc).strip()
    return text or str(exc).strip()


def _normalize_owner_code(value: str) -> str:
    text = (value or "").strip()
    digits = "".join(filter(str.isdigit, text))
    return digits or text


def _is_eaddress(value: str) -> bool:
    text = (value or "").strip()
    return bool(text and "@" in text and " " not in text)


def search_addressee(
    token_provider: TokenProvider,
    soap_client: SoapClient,
    registration_number: str,
) -> List[Mapping[str, Any]]:
    """Search for an addressee by registration number / personal code."""
    token = token_provider.get_token() if token_provider else None
    svc = soap_client.service

    try:
        query = (registration_number or "").strip()
        owner_code = _normalize_owner_code(query)

        # Build a list of payload variants to try in order.
        attempts: List[dict[str, Any]] = []
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

        last_type_error: Optional[TypeError] = None
        response = None
        for payload in attempts:
            try:
                if token:
                    try:
                        response = svc.SearchAddresseeUnit(Token=token, **payload)
                    except TypeError:
                        response = svc.SearchAddresseeUnit(**payload)
                else:
                    response = svc.SearchAddresseeUnit(**payload)
                break
            except TypeError as exc:
                last_type_error = exc
                continue
            except Exception:
                # Business / authorisation faults must not be masked.
                raise

        if response is None:
            if last_type_error is not None:
                raise last_type_error
            raise EAddressSoapError(
                "SearchAddresseeUnit call did not accept any known payload variant"
            )
    except Exception as exc:
        detail = _root_error_text(exc)
        raise EAddressSoapError(
            f"VUS SearchAddressee call failed for {registration_number}"
            + (f": {detail}" if detail else "")
        ) from exc

    data = serialize_object(response)
    if not data:
        return []

    results: Any = (
        data.get("AddresseeUnits")
        or data.get("AddresseeUnit")
        or data.get("Addressee")
        or []
    )
    if isinstance(results, dict):
        # Use `is not None` — an empty list [] is a valid (falsy) response.
        for inner_key in ("AddresseeUnit", "Addressee"):
            inner = results.get(inner_key)
            if inner is not None:
                results = inner
                break
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
        payload = {"Recipients": {"string": recipients}}
        try:
            response = soap_call(svc, "GetPublicKeyList", token, **payload)
        except TypeError:
            response = soap_call(svc, "GetPublicKeyList", token, Recipients=recipients)
    except EAddressSoapError:
        raise
    except Exception as exc:
        raise EAddressSoapError("VUS GetPublicKeyList call failed") from exc

    data = serialize_object(response)
    if not data:
        return []
    results: Any = (
        data.get("PublicKeys") or data.get("RecipientPublicKey") or []
        if isinstance(data, dict)
        else data
    )
    if isinstance(results, dict):
        results = results.get("RecipientPublicKey") or results
    if isinstance(results, dict):
        return [results]
    if isinstance(results, list):
        return [r for r in results if isinstance(r, dict)]
    return []


def validate_eaddress(
    token_provider: TokenProvider,
    soap_client: SoapClient,
    eaddresses: List[str],
    eaddress_type: Optional[str] = None,
) -> List[Mapping[str, Any]]:
    """
    Validate e-addresses in the VRAA directory.

    *eaddress_type* may be ``'NaturalPerson'``, ``'RegisteredEntity'``, or ``None``
    (no filter).

    .. warning::
        Restricted to government accounts that own DIV units.
        Commercial clients receive "Lietotājam nav tiesības uz šo darbību".
        Use :func:`search_addressee` for general lookups.
    """
    normalized = [a.strip() for a in eaddresses if (a or "").strip()]
    if not normalized:
        return []

    token = token_provider.get_token() if token_provider else None
    kwargs: dict[str, Any] = {"EAddresses": normalized}
    if eaddress_type in ("NaturalPerson", "RegisteredEntity"):
        kwargs["Type"] = eaddress_type

    try:
        response = soap_call(soap_client.service, "ValidateEAddress", token, **kwargs)
    except EAddressSoapError:
        raise
    except Exception as exc:
        raise EAddressSoapError("VUS ValidateEAddress call failed") from exc

    data = serialize_object(response) or {}
    results: Any = data.get("Results") or []
    if isinstance(results, dict):
        results = results.get("ValidationResult") or list(results.values()) or []
    if isinstance(results, dict):
        return [results]
    return [r for r in results if isinstance(r, dict)]


def get_addressee_unit(
    token_provider: TokenProvider,
    soap_client: SoapClient,
    query: str,
) -> Optional[Mapping[str, Any]]:
    """
    Fetch full addressee unit metadata for a given owner code or e-address.

    .. warning::
        Restricted to government institutions that own and manage their own DIV
        addressee units.  Commercial clients receive a permission error.
        Use :func:`search_addressee` for general lookups.
    """
    query = (query or "").strip()
    if not query:
        raise EAddressSoapError("query must not be empty")

    token = token_provider.get_token() if token_provider else None

    if _is_eaddress(query):
        # Extract registration number from e-address, e.g. _DEFAULT@90000069281 → 90000069281
        owner_code = query.split("@", 1)[1]
        kwargs: dict[str, Any] = {"AddresseeOwnerCode": owner_code, "EAddress": query}
    else:
        owner_code = _normalize_owner_code(query)
        kwargs = {"AddresseeOwnerCode": owner_code or query}

    try:
        response = soap_call(soap_client.service, "GetAddresseeUnit", token, **kwargs)
    except EAddressSoapError:
        raise
    except Exception as exc:
        raise EAddressSoapError(
            f"VUS GetAddresseeUnit call failed for {query}"
        ) from exc

    data = serialize_object(response) or {}
    unit = data.get("AddresseeUnit")
    return unit if isinstance(unit, dict) else (data or None)
