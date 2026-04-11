# PHP client for Latvia's e-Address (DIV / VUS)

Direct SOAP client for the VRAA DIV unified interface — mTLS, WSSE, XAdES envelope signing, message send/receive, attachment encryption, and addressee directory sync.
No Composer dependencies required for production use; a PSR-4 autoloader is bundled.

## Implemented operations

| Operation | Method | Status |
|-----------|--------|--------|
| `CertValidate` | `certValidateSoap()` | ✅ Validated |
| `SendMessage` | `sendMessageSoap()` | ✅ Validated |
| `GetMessageList` | `getMessageListSoap()` | ✅ Validated |
| `GetMessage` | `getMessageSoap()` | ✅ Validated |
| `GetAttachmentSection` | `getAttachmentSectionSoap()` | ✅ Validated |
| `ConfirmMessage` | `confirmMessageSoap()` | ✅ Validated |
| `SearchAddresseeUnit` | `searchAddresseeSoap()` | ✅ Validated |
| `GetPublicKeyList` | `getPublicKeyListSoap()` | ✅ Validated |
| `GetNotificationList` | `pollNotificationsSoap()` | ✅ Validated |
| `ConfirmNotificationList` | `confirmNotificationListSoap()` | ✅ Validated |
| `GetInitialAddresseeRecordList` | `getInitialAddresseeRecordListSoap()` | ✅ Validated |
| `GetChangedAddresseeRecordList` | `getChangedAddresseeRecordListSoap()` | ✅ Validated (rate-limited by VRAA) |
| `GetMessageServerConfirmation` | `getMessageServerConfirmationSoap()` | ✅ Validated |
| `ValidateEAddress` | `validateEAddressSoap()` | ⚠️ Government accounts only |
| `GetAddresseeUnit` | `getAddresseeUnitSoap()` | ⚠️ Government accounts only |

> **`ValidateEAddress` / `GetAddresseeUnit`** require a government-account permission in VRAA.
> Commercial clients receive "Lietotājam nav tiesības uz šo darbību". Use `SearchAddresseeUnit` instead.

## Validation status (2026-04-11, divtest.vraa.gov.lv)

All core operations tested against the VRAA TEST endpoint with a real VISS Root CA certificate:

- `CertValidate` → `{"status":"ok"}`
- `SendMessage` (DOC_EMPTY) → HTTP 200, MessageId returned
- `GetMessageList` → HTTP 200, 10 headers
- `GetMessage` → HTTP 200, `envelope_xml_len: 21241`
- `receive_and_confirm` → HTTP 200, `attachments_count: 1`
- `SearchAddresseeUnit` → addressee found in directory
- `GetPublicKeyList` → `key_count: 1`, RSA key returned
- `GetNotificationList` → 25 notifications returned and confirmed
- `GetInitialAddresseeRecordList` → full state addressee directory returned (auto-paginated)
- `GetChangedAddresseeRecordList` → correct SOAP call; VRAA rate-limits rapid calls
- `GetMessageServerConfirmation` → full `ServerConfirmationPart` with timestamps and VRAA signature
- `ConfirmNotificationList` → `confirmed_ids` match requested IDs

## Known VRAA limitations

| Error | Cause | Fix |
|-------|-------|-----|
| PSS.024 | `_PRIVATE@` → `_PRIVATE@` routing not supported in PROD; private-to-private delivery is disabled by design | VRAA must activate `_DEFAULT@` sender address; can then send only to state-type addressees (`_DEFAULT@`, `IEN@`) |
| PSS.045 | Envelope naming guidelines violation — in older versions of this library caused by an invalid XAdES element name (`<SignedProperties-76338609>` instead of `<SignedProperties>`). **Fixed in this library.** EINVOICE can be sent from `_PRIVATE@` accounts; PSS.045 indicates a malformed envelope, not a sender-type restriction | Upgrade to current version; ensure `SignedProperties` element has no random suffix in the tag name |
| Rate limit on `GetInitialAddresseeRecordList` | VRAA enforces minimum wait between full syncs | Implement cooldown in calling code |
| Rate limit on `GetChangedAddresseeRecordList` | Same minimum-wait rule | Use reasonable polling intervals |
| `ValidateEAddress` / `GetAddresseeUnit` | Government-account permission required | Use `SearchAddresseeUnit` for lookups |

## XAdES signing

The `DivEnvelopeSigner` produces a WS-Security + XAdES-BES signature matching the Java/.NET profile:
- `<SignedProperties Id="ds-SignedProperties">` — fixed element name (no random suffix)
- `<Signature Id="SenderSignature">` — stable ID
- Inclusive C14N (`http://www.w3.org/TR/2001/REC-xml-c14n-20010315`) for `SignedInfo`
- `ContentReference` value `"0"` (integer string, not filename/URN)

## Quick start (Docker, recommended)

```bash
# 1. Extract PEM files from p12 (once)
./test.sh --certs

# 2. Build Docker image (once)
./test.sh --build

# 3. Copy and edit env file
cp .env.test.example .env.test
# Edit .env.test — set DIV_SENDER, DIV_RECIPIENT, cert paths, etc.

# 4. Run any example
./test.sh cert_validate
./test.sh send
./test.sh get_message_list
./test.sh receive_and_confirm
./test.sh search_addressee
./test.sh poll_notifications
./test.sh get_public_key_list
./test.sh get_addressee_list          # full initial sync
DIV_LAST_VERSION=10405155 ./test.sh get_addressee_list  # delta sync
./test.sh get_server_confirm          # requires DIV_MSG_ID=<id>
./test.sh validate_eaddress           # requires government account
```

## Quick start (bare PHP, no Composer)

```bash
export DIV_WSDL_URL='https://divtest.vraa.gov.lv/Vraa.Div.WebService.UnifiedInterface/UnifiedService.svc?wsdl'
export DIV_CLIENT_CERT='/path/to/client.crt.pem'
export DIV_CLIENT_KEY='/path/to/client.key.pem'
export DIV_SIGN_CERT='/path/to/client.crt.pem'
export DIV_SIGN_KEY='/path/to/client.key.pem'
export DIV_SENDER='_PRIVATE@<REG_NO>'
export DIV_VERIFY_SSL=0

php examples/soap_cert_validate.php
php examples/soap_send.php
php examples/soap_get_message_list.php
php examples/soap_receive_and_confirm.php
```

## Usage examples

### Send a message
```php
use LatvianEinvoice\Client;
use LatvianEinvoice\Config;

// clientCertPath / clientKeyPath  — used for mTLS (curl CURLOPT_SSLCERT/SSLKEY, transport layer)
// certificatePath / privateKeyPath — used for XML signing (XAdES/WSSE envelope signature, application layer)
// For VRAA DIV both pairs are the same certificate; split params exist for setups where
// the TLS client certificate and the signing certificate differ.
$cert = '/path/to/client.crt.pem';
$key  = '/path/to/client.key.pem';

$config = new Config(
    'https://divtest.vraa.gov.lv/Vraa.Div.WebService.UnifiedInterface/UnifiedService.svc?wsdl',
    clientCertPath:  $cert,  // mTLS
    clientKeyPath:   $key,   // mTLS
    certificatePath: $cert,  // XML signing
    privateKeyPath:  $key,   // XML signing
    verifySsl:       false,
    defaultFrom:     '_PRIVATE@<REG_NO>',
);

$client = new Client($config);
$result = $client->sendMessageSoap(
    recipients:       ['_PRIVATE@<RECIPIENT>'],
    documentKindCode: 'DOC_EMPTY',
    subject:          'Test',
    bodyText:         'Hello from PHP SDK',
);
echo $result['message_id'];
```

### Receive and confirm
```php
$result = $client->getMessageListSoap(maxResultCount: 10);
// $result['body']['MessageHeaders'] — array of message headers

$msg = $client->getMessageSoap($messageId);
// $msg['envelope_xml'] — raw DIV XML envelope

$client->confirmMessageSoap($messageId);
```

### Addressee directory (full + delta)
```php
// Full initial sync — auto-paginates through all records
$result = $client->getInitialAddresseeRecordListSoap(allPages: true);
// $result['records'] — list of addressee records
// $result['continuation_token'] — non-null if more pages remain

// Incremental delta sync from a known version
$result = $client->getChangedAddresseeRecordListSoap(lastVersion: 10405155);
// $result['records'] — only records changed since that version
```

### Server confirmation
```php
$result = $client->getMessageServerConfirmationSoap($messageId);
// $result['body']['ServerConfirmationPart']['ServerTransportMetadata']['ServerReceivedTime']
```

### Notifications
```php
$result = $client->pollNotificationsSoap(maxItems: 50, autoConfirm: true);
// $result['items'] — notification list; confirmed automatically if autoConfirm=true
```

## File layout

```
src/
  Client.php                  — public API (all operations)
  Config.php                  — connection config
  Attachment.php              — attachment value object
  Soap/
    DirectSoapClient.php      — raw SOAP request builders + parsers
    DivEnvelopeSigner.php     — XAdES/WSSE signature for outbound envelopes
    WsseSigner.php            — WS-Security header for management operations
  Utils/
    Crypto.php                — AES-GCM / OAEP-CBC encryption helpers

examples/
  soap_cert_validate.php
  soap_send.php
  soap_get_message_list.php
  soap_get_message.php
  soap_receive_and_confirm.php
  soap_search_addressee.php
  soap_poll_notifications.php
  soap_confirm_notification_list.php
  soap_get_public_key_list.php
  soap_get_addressee_list.php           — initial + delta sync (DIV_LAST_VERSION)
  soap_validate_eaddress.php            — government accounts only
  soap_get_message_server_confirmation.php

test.sh                       — Docker-based test runner
.env.test.example             — environment variable template
```

## Notes

- No Composer required. The bundled PSR-4 autoloader resolves `LatvianEinvoice\*` from `src/`.
- Private keys, certificates, and `.env.test` are excluded from version control via `.gitignore`.
- VRAA PROD endpoint (`div.vraa.gov.lv`) must not be used for testing — VRAA explicitly prohibits it.
  Use `divtest.vraa.gov.lv` with the TEST certificate for all integration work.
- To send messages in production, VRAA must activate a `_DEFAULT@<regno>` sender address for each company.
  Until then, outbound routing will return PSS.024.
