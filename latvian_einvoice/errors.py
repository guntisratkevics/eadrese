from typing import Any, Mapping, Optional

class EAddressError(RuntimeError):
    """Base class for any VUS error or transport problem."""

    def __init__(self, msg: str, *, response: Optional[Mapping | Any] = None):
        super().__init__(msg)
        self.response = response


class EAddressAuthError(EAddressError):
    """Authentication or token errors (401, 403)."""
    pass


class EAddressTransportError(EAddressError):
    """Network, timeout, or SSL errors."""
    pass


class EAddressSoapError(EAddressError):
    """SOAP Faults returned by the service."""
    pass
