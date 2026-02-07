# PHP client (experimental)

This directory contains an early-stage PHP client for Latvia's e-Address (DIV / VUS).
It focuses on configuration and envelope construction. SOAP/WSSE signing is not finished yet.

## Status
- Envelope builder (SenderDocument + attachments metadata).
- AES-GCM payload encryption helper (outbound placeholder).
- DIV inbound decryption helper (RSA-OAEP SHA1 -> AES-CBC key + IV).
- Sidecar HTTP client for send/list/confirm (uses the Java sidecar API).
- SOAP transport and WS-Security signing are not implemented.

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
[$encKeyB64, $thumbB64, $symKey] = Crypto::deriveEncryptionFields(file_get_contents('/path/to/recipient.crt.pem'));

[$envelope, $attachmentsInput, $messageId] = $client->buildEnvelope(
    recipients: ['_PRIVATE@<RECIPIENT>'],
    documentKindCode: 'DOC_EMPTY',
    subject: 'Hello',
    bodyText: 'Test',
    attachments: $attachments,
    encryptionKeyB64: $encKeyB64,
    recipientThumbprintB64: $thumbB64,
    symmetricKeyBytes: $symKey
);
```

## Usage (sidecar HTTP client)
```php
use LatvianEinvoice\\SidecarClient;

$client = new SidecarClient('http://127.0.0.1:18080');
$result = $client->sendTextMessage(
    connectionId: 'P40103166694_01',
    recipient: '_GATIS@90001733697',
    subject: 'PHP smoke test',
    body: 'Hello from PHP',
    unsigned: false
);
```

## Composer
```bash
composer install
```

## Notes
- This code is experimental and not production ready.
- Do not copy private keys or certificates into the repository.
