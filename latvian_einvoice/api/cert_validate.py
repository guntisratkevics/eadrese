"""cert_validate — connectivity + certificate check via SearchAddresseeUnit."""
from typing import Any, List, Mapping

from ..auth import TokenProvider
from ..soap.client import SoapClient
from .addressbook import search_addressee


def cert_validate(
    token_provider: TokenProvider,
    soap_client: SoapClient,
    lookup_values: List[str],
) -> Mapping[str, Any]:
    """
    Validate SOAP connectivity and certificate by attempting a
    ``SearchAddresseeUnit`` lookup.

    Tries each value in *lookup_values* in order; returns
    ``{"status": "ok"}`` on the first successful result.
    Falls back to ``{"status": "error"}`` with error details if every
    attempt fails.

    Returns::

        {
            "status": "ok" | "error",
            "message": str,
            "lookup_value": str,          # present on success
            "attempted_values": [str, ...],
            "errors": [str, ...],         # present on error
        }
    """
    attempted: List[str] = []
    attempted_set: set[str] = set()
    errors: List[str] = []

    for raw in lookup_values:
        value = (raw or "").strip()
        if not value or value in attempted_set:
            continue
        attempted.append(value)
        attempted_set.add(value)
        try:
            results = search_addressee(token_provider, soap_client, value)
            if results:
                return {
                    "status": "ok",
                    "message": "Certificate valid and connectivity working.",
                    "lookup_value": value,
                    "attempted_values": attempted,
                }
            errors.append(f"{value}: no results")
        except Exception as exc:
            msg = str(exc).strip() or type(exc).__name__
            errors.append(f"{value}: {msg}")

    message = next(iter(errors), "Certificate validation lookup failed (no values provided).")
    return {
        "status": "error",
        "message": message,
        "attempted_values": attempted,
        "errors": errors,
    }
