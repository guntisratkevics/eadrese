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

$wsdlUrl    = getenv('DIV_WSDL_URL')    ?: 'https://divtest.vraa.gov.lv/Vraa.Div.WebService.UnifiedInterface/UnifiedService.svc?wsdl';
$clientCert = getenv('DIV_CLIENT_CERT') ?: '';
$clientKey  = getenv('DIV_CLIENT_KEY')  ?: '';
$signCert   = getenv('DIV_SIGN_CERT')   ?: $clientCert;
$signKey    = getenv('DIV_SIGN_KEY')    ?: $clientKey;
$sender     = getenv('DIV_SENDER')      ?: '_PRIVATE@<REG_NO>';
$verifySsl  = (getenv('DIV_VERIFY_SSL') ?: '0') !== '0';

// Comma/space/semicolon-separated list of e-addresses to validate.
// Falls back to DIV_SENDER if not set.
$rawAddresses = trim((string)getenv('DIV_EADDRESSES'));
if ($rawAddresses === '') {
    $rawAddresses = trim((string)getenv('DIV_SENDER'));
}
if ($rawAddresses === '') {
    fwrite(STDERR, "Error: set DIV_EADDRESSES with one or more e-addresses to validate.\n");
    exit(1);
}

$eAddresses = array_values(array_filter(
    array_map('trim', preg_split('/[\s,;]+/', $rawAddresses) ?: [])
));

// Optional type filter: 'NaturalPerson' or 'RegisteredEntity'.
$type = trim((string)getenv('DIV_EADDRESS_TYPE')) ?: null;
if ($type !== null && !in_array($type, ['NaturalPerson', 'RegisteredEntity'], true)) {
    fwrite(STDERR, "Warning: DIV_EADDRESS_TYPE must be 'NaturalPerson' or 'RegisteredEntity' (ignoring).\n");
    $type = null;
}

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
$result = $client->validateEAddressSoap($eAddresses, $type);

$debugDir = getenv('DIV_DEBUG_DIR') ?: '';
if ($debugDir !== '') {
    if (!is_dir($debugDir)) {
        @mkdir($debugDir, 0700, true);
    }
    @file_put_contents(rtrim($debugDir, '/') . '/php_request.xml',  (string)($result['request_xml'] ?? ''));
    @file_put_contents(rtrim($debugDir, '/') . '/php_response.raw', (string)($result['raw'] ?? ''));
}

$body    = is_array($result['body'] ?? null) ? $result['body'] : [];
$results = is_array($result['results'] ?? null) ? $result['results'] : [];

$out = [
    'status'       => $result['status'] ?? null,
    'queried'      => $eAddresses,
    'result_count' => count($results),
    'results'      => $results,
];

if (array_key_exists('Fault', $body)) {
    $out['fault'] = $body['Fault'];
    unset($out['results']);
}

echo json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL;
