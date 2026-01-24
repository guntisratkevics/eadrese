# Python E-Adrese Client Specification

## 1. Overview
This library (`latvian_einvoice`) is a pure Python implementation for the Latvian E-Address (VRAA VUS) and VID EDS e-invoice integration, designed to work without official Java/.NET libraries.

## 2. Requirements Deducing (from instructions)

### 2.1 Endpoints
*   **WSDL**: `https://div.vraa.gov.lv/UnifiedService.svc?wsdl` (Production)
*   **Token URL**: `https://div.vraa.gov.lv/Auth/token`
*   **Environment**: Supports `PROD` and `TEST` (configured via URLs).

### 2.2 Authentication
*   **Protocol**: OAuth 2.0 Client Credentials Grant.
*   **Credentials**: `client_id`, `client_secret`.
*   **Token Caching**: Tokens must be cached until `expires_in - 60s` to avoid rate limits.
*   **TLS/SSL**: Mandatory. Mutual TLS (mTLS) with client certificate (`certificate`, `private_key`) is supported and required for VUS.

### 2.3 Message Model
*   **Mandatory Fields**:
    *   `From`: Sender personal code or registration number.
    *   `To`: Recipient personal code (or list of recipients).
    *   `DocumentKind`: Must be `EINVOICE` for e-invoices.
    *   `Attachments`: At least one XML file (UBL format) is expected for e-invoices.
*   **Aliases (Test Environment)**:
    *   Sender: `_DEFAULT@90000000000`
    *   Recipient: `_PRIVATE@10000000000`

### 2.4 Receiving & Confirmation
*   `GetNextMessage`: Retrieves the next available message from the queue. Configurable to include attachments.
*   `ConfirmMessage`: Acknowledges receipt of a specific `message_id`. This is critical to remove the message from the queue.

### 2.5 Attachments
*   Base64 encoded content.
*   Structure: `FileName`, `MimeType`, `Content`.

## 3. Architecture
The package follows a modular structure:
*   `client.py`: Main Facade.
*   `auth.py`: Token management.
*   `soap/`: Low-level SOAP handling (Zeep).
*   `api/`: Functional implementations for Send, Receive, Confirm, Search.

## 4. Configuration
Key configuration parameters in `EAddressConfig`:
*   `vid_subaddress_auto`: Automatically adds VID as a recipient for e-invoices.
*   `vid_subaddress`: Configurable VID address (defaults to PROD/TEST values based on environment).
