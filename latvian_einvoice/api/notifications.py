"""GetNotificationList / ConfirmNotificationList / poll_notifications."""
from typing import Any, List, Mapping, Optional

from zeep.helpers import serialize_object

from ..auth import TokenProvider
from ..errors import EAddressSoapError
from ..soap.client import SoapClient
from ._soap_utils import extract_list, soap_call


def get_notification_list(
    token_provider: TokenProvider,
    soap_client: SoapClient,
    max_items: int = 50,
) -> Mapping[str, Any]:
    """Fetch pending notifications (raw response dict)."""
    token = token_provider.get_token() if token_provider else None
    try:
        response = soap_call(
            soap_client.service,
            "GetNotificationList",
            token,  # gitleaks:allow -- runtime OAuth token, not a literal credential
            MaxResultCount=max_items,
        )
    except EAddressSoapError:
        raise
    except Exception as exc:
        raise EAddressSoapError("VUS GetNotificationList call failed") from exc
    return serialize_object(response) or {}


def confirm_notification_list(
    token_provider: TokenProvider,
    soap_client: SoapClient,
    notification_ids: List[int],
) -> List[int]:
    """Confirm a list of notification IDs. Returns the confirmed IDs."""
    normalized = [int(nid) for nid in notification_ids if nid is not None]
    if not normalized:
        return []
    token = token_provider.get_token() if token_provider else None
    try:
        soap_call(
            soap_client.service,
            "ConfirmNotificationList",
            token,
            NotificationIds=normalized,
        )
    except EAddressSoapError:
        raise
    except Exception as exc:
        raise EAddressSoapError("VUS ConfirmNotificationList call failed") from exc
    return normalized


def poll_notifications(
    token_provider: TokenProvider,
    soap_client: SoapClient,
    max_items: int = 50,
    auto_confirm: bool = True,
) -> Mapping[str, Any]:
    """
    Poll notifications with optional auto-confirm.

    Returns::

        {
            "items": [<notification dict>, ...],
            "has_more_data": bool,
            "confirmed_ids": [int, ...],
        }
    """
    limit = max(min(max_items, 200), 1)
    items: List[Mapping[str, Any]] = []
    confirmed_ids: List[int] = []
    has_more_data = False
    seen: set[int] = set()

    while len(items) < limit:
        remaining = limit - len(items)
        data = get_notification_list(token_provider, soap_client, max_items=remaining)
        batch = extract_list(data, "Notifications", "Notification")
        has_more_data = bool(data.get("HasMoreData", False))
        if not batch:
            break

        batch_ids: List[int] = []
        filtered: List[Mapping[str, Any]] = []
        for item in batch:
            raw_id = item.get("Id") or item.get("id") or item.get("NotificationId")
            nid: Optional[int] = None
            if raw_id is not None:
                try:
                    nid = int(raw_id)
                except (TypeError, ValueError):
                    pass
            if nid is not None:
                if nid in seen:
                    continue
                seen.add(nid)
                batch_ids.append(nid)
            filtered.append(item)

        if not filtered:
            break

        # Honour the limit even when the service returns more items than requested.
        available = limit - len(items)
        items.extend(filtered[:available])

        if auto_confirm and batch_ids:
            try:
                confirmed_ids.extend(
                    confirm_notification_list(token_provider, soap_client, batch_ids)
                )
            except EAddressSoapError:
                break

        if not has_more_data:
            break

    return {
        "items": items,
        "has_more_data": has_more_data,
        "confirmed_ids": confirmed_ids,
    }
