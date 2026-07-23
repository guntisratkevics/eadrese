"""GetInitialAddresseeRecordList / GetChangedAddresseeRecordList."""
from typing import Any, List, Mapping, Optional

from zeep.helpers import serialize_object

from ..auth import TokenProvider
from ..errors import EAddressSoapError
from ..soap.client import SoapClient
from ._soap_utils import extract_list, soap_call


def _latest_version(records: List[Mapping[str, Any]]) -> Optional[int]:
    versions: List[int] = []
    for record in records:
        raw = record.get("Version")
        try:
            versions.append(int(raw))
        except Exception:
            continue
    return max(versions) if versions else None


def get_initial_addressee_record_list(
    token_provider: TokenProvider,
    soap_client: SoapClient,
    continuation_token: Optional[str] = None,
    all_pages: bool = True,
) -> Mapping[str, Any]:
    """
    Full initial sync of the VRAA addressee directory.

    Automatically paginates through all pages when ``all_pages=True``.
    Pass ``continuation_token`` to resume from a previous call (single-page mode).

    Returns::

        {
            "records": [<addressee dict>, ...],
            "continuation_token": str | None,
            "latest_version": int | None,
            "record_count": int,
        }
    """
    all_records: List[Mapping[str, Any]] = []
    current_token = continuation_token
    seen_tokens: set[str] = set()
    if current_token:
        seen_tokens.add(current_token)

    while True:
        fn = getattr(soap_client.service, "GetInitialAddresseeRecordList", None)
        if fn is None:
            raise EAddressSoapError("Service has no GetInitialAddresseeRecordList method")
        kwargs: dict[str, Any] = {"Token": current_token} if current_token else {}
        try:
            # This operation uses a body field named ``Token`` for continuation paging.
            # Passing the OAuth token here collides with that field and breaks paging.
            # Authentication for this operation is handled by the SOAP client/cert context.
            response = fn(**kwargs)
        except EAddressSoapError:
            raise
        except Exception as exc:
            raise EAddressSoapError(
                f"VUS GetInitialAddresseeRecordList call failed: {exc}"
            ) from exc

        data = serialize_object(response) or {}
        all_records.extend(extract_list(data, "AddresseeRecords", "AddresseeRecord"))
        next_token = (data.get("ContinuationToken") or "").strip() or None

        # Single-page mode: caller supplied an explicit starting token.
        if continuation_token is not None:
            current_token = next_token
            break
        if not all_pages or next_token is None:
            current_token = next_token
            break
        if next_token in seen_tokens:
            raise EAddressSoapError(
                "VUS GetInitialAddresseeRecordList pagination stalled "
                f"at continuation token {next_token!r}"
            )
        seen_tokens.add(next_token)
        current_token = next_token

    return {
        "records": all_records,
        "continuation_token": current_token,
        "latest_version": _latest_version(all_records),
        "record_count": len(all_records),
    }


def get_changed_addressee_record_list(
    token_provider: TokenProvider,
    soap_client: SoapClient,
    last_version: int = 0,
    all_pages: bool = False,
) -> Mapping[str, Any]:
    """
    Incremental sync of the VRAA addressee directory since *last_version*.

    Use the highest ``Version`` value from a previous sync as ``last_version``.

    Returns::

        {
            "records": [<addressee dict>, ...],
            "has_more_data": bool,
            "latest_version": int | None,
            "record_count": int,
        }
    """
    token = token_provider.get_token() if token_provider else None
    all_records: List[Mapping[str, Any]] = []
    current_last_version = int(last_version)
    has_more_data = False

    while True:
        try:
            response = soap_call(
                soap_client.service,
                "GetChangedAddresseeRecordList",
                token,
                LastVersion=current_last_version,
            )
        except EAddressSoapError:
            raise
        except Exception as exc:
            raise EAddressSoapError(
                f"VUS GetChangedAddresseeRecordList call failed: {exc}"
            ) from exc

        data = serialize_object(response) or {}
        batch_records = extract_list(data, "AddresseeRecords", "AddresseeRecord")
        all_records.extend(batch_records)
        has_more_data = bool(data.get("HasMoreData", False))

        if not all_pages or not has_more_data:
            break

        batch_latest_version = _latest_version(batch_records)
        if batch_latest_version is None or batch_latest_version <= current_last_version:
            raise EAddressSoapError(
                "VUS GetChangedAddresseeRecordList pagination stalled: HasMoreData=true but no newer Version was returned"
            )
        current_last_version = batch_latest_version

    return {
        "records": all_records,
        "has_more_data": has_more_data,
        "latest_version": _latest_version(all_records),
        "record_count": len(all_records),
    }
