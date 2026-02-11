# PHP client (experimental)

This directory contains an early-stage PHP client for Latvia's e-Address (DIV / VUS).
It focuses on configuration, envelope construction, and experimental direct SOAP SendMessage signing (WSSE + SenderDocument).

## Status
- Envelope builder (SenderDocument + attachments metadata).
- AES-GCM payload encryption helper (outbound placeholder).
- OAEP+AES-CBC outbound helper (DIV-aligned mode).
- DIV inbound decryption helper (RSA-OAEP SHA1 -> AES-CBC key + IV).
- Sidecar HTTP client for send/list/confirm (uses the Java sidecar API).
- Direct SOAP `SendMessage` (mTLS + WSSE + SenderDocument signature) is implemented and validated from STAGE.
- Direct SOAP `GetMessageList`, `GetMessage`, `GetAttachmentSection`, and `ConfirmMessage` are implemented.
- Decoder helpers for attachment section stitching + decrypt/decompress are implemented.

## Validation Status (as of 2026-02-11)
Tested and working
- Direct SOAP `SendMessage` from STAGE (`php examples/soap_send.php`) returns HTTP 200 and MessageId.
- Direct SOAP `GetMessageList` from STAGE (`php examples/soap_get_message_list.php`) returns HTTP 200.
- MIME normalization for encrypted `text/*` attachments is applied in envelope builder.

Implemented but not yet validated end-to-end
- Full receive/decrypt flow against real inbound messages with attachments (test inbox currently empty).
- `ConfirmMessage` against real inbound messages.

## Usage (building envelope)
```php
use LatvianEinvoice\Attachment;
use LatvianEinvoice\Client;
use LatvianEinvoice\Config;
use LatvianEinvoice\Utils\Crypto;

$config = new Config(
    'https://divtest.vraa.gov.lv/Vraa.Div.WebService.UnifiedInterface/UnifiedService.svc?wsdl',
    clientCertPath: '/path/to/client.crt.pem',
    clientKeyPath: '/path/to/client.key.pem',
    certificatePath: '/path/to/client.crt.pem',
    privateKeyPath: '/path/to/client.key.pem',
    verifySsl: false,
    defaultFrom: '_PRIVATE@<REG_NO>'
);

$client = new Client($config);

$attachments = [new Attachment('inv.xml', '<xml/>', 'application/xml')];
[$encKeyB64, $thumbB64, $symKey, $symIv] = Crypto::deriveEncryptionFieldsOaepCbc(
    file_get_contents('/path/to/recipient.crt.pem')
);

[$envelope, $attachmentsInput, $messageId] = $client->buildEnvelope(
    recipients: ['_PRIVATE@<RECIPIENT>'],
    documentKindCode: 'DOC_EMPTY',
    subject: 'Hello',
    bodyText: 'Test',
    attachments: $attachments,
    encryptionKeyB64: $encKeyB64,
    recipientThumbprintB64: $thumbB64,
    symmetricKeyBytes: $symKey,
    symmetricIvBytes: $symIv,
    encryptionMode: 'oaep_cbc'
);
```

## Usage (sidecar HTTP client)
```php
use LatvianEinvoice\SidecarClient;

$client = new SidecarClient('http://127.0.0.1:18080');
$result = $client->sendTextMessage(
    connectionId: 'P<REG_NO>_01',
    recipient: '_PRIVATE@<RECIPIENT_REG_NO>',
    subject: 'PHP smoke test',
    body: 'Hello from PHP',
    unsigned: false
);
```

Example script (reads env vars: `DIV_SIDECAR_URL`, `DIV_CONNECTION_ID`, `DIV_RECIPIENT`):
```bash
php examples/sidecar_send.php
```

## Usage (direct SOAP SendMessage)
Requires mTLS files (`DIV_CLIENT_CERT`, `DIV_CLIENT_KEY`) and signing files (`DIV_SIGN_CERT`, `DIV_SIGN_KEY`).
By default, the example uses TEST WSDL and `DIV_VERIFY_SSL=0`.

```bash
composer install
DIV_WSDL_URL='https://divtest.vraa.gov.lv/Vraa.Div.WebService.UnifiedInterface/UnifiedService.svc?wsdl' \
DIV_CLIENT_CERT='/path/to/client.crt.pem' \
DIV_CLIENT_KEY='/path/to/client.key.pem' \
DIV_SIGN_CERT='/path/to/client.crt.pem' \
DIV_SIGN_KEY='/path/to/client.key.pem' \
DIV_SENDER='_PRIVATE@<REG_NO>' \
DIV_RECIPIENT='_PRIVATE@<RECIPIENT_REG_NO>' \
DIV_VERIFY_SSL=0 \
php examples/soap_send.php
```

Running via Docker on a host that exposes the sidecar on `127.0.0.1`:
```bash
sudo docker run --rm --network host -v /path/to/php:/app -w /app php:8.2-cli php examples/sidecar_send.php
```

## Composer
```bash
composer install
```

## Notes
- This code is experimental and not production ready.
- Do not copy private keys or certificates into the repository.

## Support PHP Development
- https://revolut.me/guntisha2j
