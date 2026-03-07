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

$maxResultCount = (int)(getenv('DIV_MAX_RESULT_COUNT') ?: '50');

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
$result = $client->getNotificationListSoap($maxResultCount);

$debugDir = getenv('DIV_DEBUG_DIR') ?: '';
if ($debugDir !== '') {
    if (!is_dir($debugDir)) {
        @mkdir($debugDir, 0700, true);
    }
    @file_put_contents(rtrim($debugDir, '/') . '/php_request.xml', (string)($result['request_xml'] ?? ''));
    @file_put_contents(rtrim($debugDir, '/') . '/php_response.raw', (string)($result['raw'] ?? ''));
}

$body = is_array($result['body'] ?? null) ? $result['body'] : [];
$notifications = [];
if (is_array($body['Notifications'] ?? null)) {
    $notificationBlock = $body['Notifications']['Notification'] ?? [];
    if (is_array($notificationBlock) && array_key_exists('Id', $notificationBlock)) {
        $notifications = [$notificationBlock];
    } elseif (is_array($notificationBlock)) {
        $notifications = $notificationBlock;
    }
}

$out = [
    'status' => $result['status'] ?? null,
    'has_more_data' => (bool)($body['HasMoreData'] ?? false),
    'notification_count' => is_array($notifications) ? count($notifications) : 0,
];

if ((getenv('DIV_PRINT_NOTIFICATIONS') ?: '0') !== '0') {
    $out['notifications'] = $notifications;
}

if (is_array($body) && array_key_exists('Fault', $body)) {
    $out['fault'] = $body['Fault'];
}

echo json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
