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

function parseLookupValues(string $raw): array
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

$lookupRaw = trim((string)(getenv('DIV_LOOKUP_VALUES') ?: ''));
$lookupValues = parseLookupValues($lookupRaw);
if (empty($lookupValues)) {
    // Derive from DIV_SENDER if available, e.g. _PRIVATE@40001234567 -> ['40001234567', 'LV40001234567']
    $regNo = preg_replace('/^[^@]+@/', '', trim((string)getenv('DIV_SENDER')));
    $lookupValues = $regNo !== '' ? [$regNo, 'LV' . $regNo] : [];
}
if (empty($lookupValues)) {
    fwrite(STDERR, "Error: set DIV_LOOKUP_VALUES or DIV_SENDER env var.\n");
    exit(1);
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
$result = $client->certValidateSoap($lookupValues);

echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
