<?php

declare(strict_types=1);

// Local PSR-4 autoloader (avoids requiring Composer on target hosts).
spl_autoload_register(static function (string $class): void {
    $prefix = 'LatvianEinvoice\\';
    $baseDir = __DIR__ . '/../src/';
    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }
    $relative = substr($class, $len);
    $file = $baseDir . str_replace('\\', '/', $relative) . '.php';
    if (is_file($file)) {
        require_once $file;
    }
});

use LatvianEinvoice\Client;
use LatvianEinvoice\Config;

$wsdlUrl = getenv('DIV_WSDL_URL') ?: 'https://divtest.vraa.gov.lv/Vraa.Div.WebService.UnifiedInterface/UnifiedService.svc?wsdl';

$clientCertPath = getenv('DIV_CLIENT_CERT') ?: '';
$clientKeyPath = getenv('DIV_CLIENT_KEY') ?: '';
$signCertPath = getenv('DIV_SIGN_CERT') ?: $clientCertPath;
$signKeyPath = getenv('DIV_SIGN_KEY') ?: $clientKeyPath;

$sender = getenv('DIV_SENDER') ?: '_PRIVATE@<REG_NO>';
$verifySsl = (getenv('DIV_VERIFY_SSL') ?: '0') !== '0';

$cfg = new Config(
    $wsdlUrl,
    clientCertPath: $clientCertPath !== '' ? $clientCertPath : null,
    clientKeyPath: $clientKeyPath !== '' ? $clientKeyPath : null,
    certificatePath: $signCertPath !== '' ? $signCertPath : null,
    privateKeyPath: $signKeyPath !== '' ? $signKeyPath : null,
    verifySsl: $verifySsl,
    defaultFrom: $sender,
);
$client = new Client($cfg);

$messageId = trim((string)(getenv('DIV_MESSAGE_ID') ?: ''));
if ($messageId === '') {
    $list = $client->getMessageListSoap(10);
    $body = is_array($list['body'] ?? null) ? $list['body'] : null;
    $headers = is_array($body['MessageHeaders'] ?? null) ? $body['MessageHeaders'] : [];
    $first = is_array($headers) && count($headers) > 0 ? $headers[0] : null;
    $messageId = is_array($first) ? (string)($first['MessageId'] ?? '') : '';
}
if ($messageId === '') {
    fwrite(STDERR, "No messages found. Set DIV_MESSAGE_ID or ask VRAA to send test messages.\n");
    exit(2);
}

$res = $client->getMessageDecodedSoap($messageId, stitchSections: true, decrypt: true);
$body = is_array($res['body'] ?? null) ? $res['body'] : null;

$attachments = [];
if (is_array($body) && is_array($body['AttachmentsOutput'] ?? null)) {
    $attachments = $body['AttachmentsOutput']['AttachmentOutput'] ?? [];
}
if (is_array($attachments) && array_key_exists('ContentId', $attachments)) {
    $attachments = [$attachments];
}

$debugDir = getenv('DIV_DEBUG_DIR') ?: '';
if ($debugDir !== '' && is_array($attachments)) {
    if (!is_dir($debugDir)) {
        @mkdir($debugDir, 0700, true);
    }
    foreach ($attachments as $i => $att) {
        if (!is_array($att)) {
            continue;
        }
        $name = (string)($att['Name'] ?? ('attachment_' . $i));
        $safe = preg_replace('/[^A-Za-z0-9._-]+/', '_', $name) ?: ('attachment_' . $i);
        if (isset($att['DecryptedContent']) && is_string($att['DecryptedContent'])) {
            @file_put_contents(rtrim($debugDir, '/') . '/' . $safe, $att['DecryptedContent']);
        } elseif (isset($att['Contents']) && is_string($att['Contents'])) {
            $raw = base64_decode($att['Contents'], true);
            if ($raw !== false) {
                @file_put_contents(rtrim($debugDir, '/') . '/' . $safe . '.enc', $raw);
            }
        }
    }
}

$out = [
    'status' => $res['status'] ?? null,
    'message_id' => $messageId,
    'attachments_count' => is_array($attachments) ? count($attachments) : null,
];
echo json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;

if ((getenv('DIV_CONFIRM') ?: '0') !== '0') {
    $confirm = $client->confirmMessageSoap($messageId);
    $out2 = [
        'confirm_status' => $confirm['status'] ?? null,
        'fault' => $confirm['body']['Fault'] ?? null,
    ];
    echo json_encode($out2, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
}

