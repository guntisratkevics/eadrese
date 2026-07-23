"""Shared low-level helpers for SOAP service calls."""
from typing import Any, List, Mapping, Optional

from ..errors import EAddressSoapError


def soap_call(svc: Any, method: str, token: Optional[str], **kwargs: Any) -> Any:
    """
    Call ``svc.<method>(**kwargs)`` with optional OAuth token.

    Tries ``Token=token`` first; falls back to without ``Token`` on
    :exc:`TypeError` so the same code works with both older WSDL bindings
    (no ``Token`` field in the input element) and current ones.

    Raises :class:`~latvian_einvoice.errors.EAddressSoapError` when the
    service object has no such method.
    """
    fn = getattr(svc, method, None)
    if fn is None:
        raise EAddressSoapError(f"Service has no {method} method")
    if token:
        try:
            return fn(Token=token, **kwargs)
        except TypeError:
            pass
    return fn(**kwargs)


def extract_list(container: Any, *nested_keys: str) -> List[Mapping[str, Any]]:
    """
    Walk *container* through *nested_keys* and return the final value as a
    normalised list of dicts.

    Example::

        extract_list(data, "Notifications", "Notification")
        # → data["Notifications"]["Notification"] normalised to list[dict]

    Rules:
    - If any intermediate key is missing or falsy, return ``[]``.
    - If the final value is a dict it is wrapped in a list.
    - Non-dict items are filtered out.
    """
    current: Any = container
    for key in nested_keys:
        if not isinstance(current, dict):
            return []
        current = current.get(key)
        if not current:
            return []
    if isinstance(current, dict):
        return [current]
    if isinstance(current, list):
        return [item for item in current if isinstance(item, dict)]
    return []
