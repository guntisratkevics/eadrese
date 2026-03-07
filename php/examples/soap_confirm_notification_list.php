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

function parseNotificationIds(string $raw): array
{
    if ($raw === '') {
        return [];
    }
    $parts = preg_split('/[\s,;]+/', $raw) ?: [];
    $ids = [];
    foreach ($parts as $part) {
        $part = trim($part);
        if ($part === '' || !preg_match('/^\d+$/', $part)) {
            continue;
        }
        $id = (int)$part;
        if ($id > 0) {
            $ids[$id] = $id;
        }
    }
    return array_values($ids);
}

$wsdlUrl = getenv('DIV_WSDL_URL') ?: 'https://divtest.vraa.gov.lv/Vraa.Div.WebService.UnifiedInterface/UnifiedService.svc?wsdl';
$clientCertPath = getenv('DIV_CLIENT_CERT') ?: '';
$clientKeyPath = getenv('DIV_CLIENT_KEY') ?: '';
$signCertPath = getenv('DIV_SIGN_CERT') ?: $clientCertPath;
$signKeyPath = getenv('DIV_SIGN_KEY') ?: $clientKeyPath;
$sender = getenv('DIV_SENDER') ?: '_PRIVATE@<REG_NO>';
$verifySsl = (getenv('DIV_VERIFY_SSL') ?: '0') !== '0';
$idsRaw = trim((string)(getenv('DIV_NOTIFICATION_IDS') ?: ''));
$notificationIds = parseNotificationIds($idsRaw);

if (empty($notificationIds)) {
    fwrite(STDERR, "Set DIV_NOTIFICATION_IDS with one or more numeric notification IDs.\n");
    exit(2);
}

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
$result = $client->confirmNotificationListSoap($notificationIds);

$debugDir = getenv('DIV_DEBUG_DIR') ?: '';
if ($debugDir !== '') {
    if (!is_dir($debugDir)) {
        @mkdir($debugDir, 0700, true);
    }
    @file_put_contents(rtrim($debugDir, '/') . '/php_request.xml', (string)($result['request_xml'] ?? ''));
    @file_put_contents(rtrim($debugDir, '/') . '/php_response.raw', (string)($result['raw'] ?? ''));
}

$body = is_array($result['body'] ?? null) ? $result['body'] : [];
$out = [
    'status' => $result['status'] ?? null,
    'requested_ids' => $notificationIds,
    'confirmed_ids' => $result['confirmed_ids'] ?? [],
];
if (array_key_exists('Fault', $body)) {
    $out['fault'] = $body['Fault'];
}

echo json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
