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

$wsdlUrl      = getenv('DIV_WSDL_URL')    ?: 'https://divtest.vraa.gov.lv/Vraa.Div.WebService.UnifiedInterface/UnifiedService.svc?wsdl';
$clientCert   = getenv('DIV_CLIENT_CERT') ?: '';
$clientKey    = getenv('DIV_CLIENT_KEY')  ?: '';
$signCert     = getenv('DIV_SIGN_CERT')   ?: $clientCert;
$signKey      = getenv('DIV_SIGN_KEY')    ?: $clientKey;
$sender       = getenv('DIV_SENDER')      ?: '_PRIVATE@<REG_NO>';
$verifySsl    = (getenv('DIV_VERIFY_SSL') ?: '0') !== '0';

// Optional: pass a ContinuationToken to fetch a single page.
// Leave empty to auto-paginate through ALL records (may take a while for large directories).
$token        = trim((string)getenv('DIV_CONTINUATION_TOKEN'));
$allPages     = (getenv('DIV_ALL_PAGES') ?: '1') !== '0';
// Limit printed records to avoid flooding the terminal.
$printMax     = (int)(getenv('DIV_PRINT_MAX') ?: '5');

$cfg = new Config(
    $wsdlUrl,
    clientCertPath:  $clientCert !== '' ? $clientCert : null,
    clientKeyPath:   $clientKey  !== '' ? $clientKey  : null,
    certificatePath: $signCert   !== '' ? $signCert   : null,
    privateKeyPath:  $signKey    !== '' ? $signKey    : null,
    verifySsl:       $verifySsl,
    defaultFrom:     $sender,
);

$client = new Client($cfg);
$result = $client->getInitialAddresseeRecordListSoap(
    $token !== '' ? $token : null,
    $allPages
);

$debugDir = getenv('DIV_DEBUG_DIR') ?: '';
if ($debugDir !== '') {
    if (!is_dir($debugDir)) {
        @mkdir($debugDir, 0700, true);
    }
    @file_put_contents(rtrim($debugDir, '/') . '/php_request.xml',  (string)($result['request_xml'] ?? ''));
    @file_put_contents(rtrim($debugDir, '/') . '/php_response.raw', (string)($result['raw'] ?? ''));
}

$body    = is_array($result['body'] ?? null) ? $result['body'] : [];
$records = is_array($result['records'] ?? null) ? $result['records'] : [];

$out = [
    'status'             => $result['status'] ?? null,
    'record_count'       => count($records),
    'continuation_token' => $result['continuation_token'] ?? null,
];

if (array_key_exists('Fault', $body)) {
    $out['fault'] = $body['Fault'];
} elseif ($printMax > 0 && !empty($records)) {
    $out['first_records'] = array_slice($records, 0, $printMax);
}

echo json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL;
