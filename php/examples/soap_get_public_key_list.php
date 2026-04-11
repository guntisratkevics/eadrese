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

function parseRecipients(string $raw): array
{
    $parts = preg_split('/[\s,;]+/', $raw) ?: [];
    $values = [];
    foreach ($parts as $part) {
        $value = trim($part);
        if ($value === '') {
            continue;
        }
        if (!in_array($value, $values, true)) {
            $values[] = $value;
        }
    }
    return $values;
}

$wsdlUrl = getenv('DIV_WSDL_URL') ?: 'https://divtest.vraa.gov.lv/Vraa.Div.WebService.UnifiedInterface/UnifiedService.svc?wsdl';
$clientCertPath = getenv('DIV_CLIENT_CERT') ?: '';
$clientKeyPath = getenv('DIV_CLIENT_KEY') ?: '';
$signCertPath = getenv('DIV_SIGN_CERT') ?: $clientCertPath;
$signKeyPath = getenv('DIV_SIGN_KEY') ?: $clientKeyPath;
$sender = getenv('DIV_SENDER') ?: '_PRIVATE@<REG_NO>';
$verifySsl = (getenv('DIV_VERIFY_SSL') ?: '0') !== '0';

$rawRecipients = trim((string)getenv('DIV_RECIPIENTS'));
$recipients = parseRecipients($rawRecipients);
if (empty($recipients)) {
    fwrite(STDERR, "Set DIV_RECIPIENTS with one or more e-addresses.\n");
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
$result = $client->getPublicKeyListSoap($recipients);

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
    'recipients' => $recipients,
    'key_count' => is_array($result['keys'] ?? null) ? count($result['keys']) : 0,
];
if ((getenv('DIV_PRINT_KEYS') ?: '0') !== '0') {
    $out['keys'] = $result['keys'] ?? [];
}
if (array_key_exists('Fault', $body)) {
    $out['fault'] = $body['Fault'];
}

echo json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
