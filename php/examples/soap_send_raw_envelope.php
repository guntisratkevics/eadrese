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

use LatvianEinvoice\Config;
use LatvianEinvoice\Soap\DirectSoapClient;

$wsdlUrl = getenv('DIV_WSDL_URL') ?: 'https://divtest.vraa.gov.lv/Vraa.Div.WebService.UnifiedInterface/UnifiedService.svc?wsdl';

$clientCertPath = getenv('DIV_CLIENT_CERT') ?: '';
$clientKeyPath = getenv('DIV_CLIENT_KEY') ?: '';
$signCertPath = getenv('DIV_SIGN_CERT') ?: $clientCertPath;
$signKeyPath = getenv('DIV_SIGN_KEY') ?: $clientKeyPath;

$verifySsl = (getenv('DIV_VERIFY_SSL') ?: '0') !== '0';

$envelopePath = getenv('DIV_ENVELOPE_XML_PATH') ?: '';
if ($envelopePath === '' || !is_file($envelopePath)) {
    throw new RuntimeException('Set DIV_ENVELOPE_XML_PATH to an existing DIV Envelope .xml file');
}
$envelopeXml = file_get_contents($envelopePath);
if ($envelopeXml === false) {
    throw new RuntimeException('Failed to read envelope XML: ' . $envelopePath);
}

$cfg = new Config(
    $wsdlUrl,
    clientCertPath: $clientCertPath !== '' ? $clientCertPath : null,
    clientKeyPath: $clientKeyPath !== '' ? $clientKeyPath : null,
    certificatePath: $signCertPath !== '' ? $signCertPath : null,
    privateKeyPath: $signKeyPath !== '' ? $signKeyPath : null,
    verifySsl: $verifySsl,
    // Not used for raw envelope send, but keep non-empty for consistency.
    defaultFrom: getenv('DIV_SENDER') ?: '_PRIVATE@<REG_NO>',
);

$soap = new DirectSoapClient($cfg);
$result = $soap->sendEnvelopeXml((string)$envelopeXml);

$debugDir = getenv('DIV_DEBUG_DIR') ?: '';
if ($debugDir !== '') {
    if (!is_dir($debugDir)) {
        @mkdir($debugDir, 0700, true);
    }
    @file_put_contents(rtrim($debugDir, '/') . '/php_request.xml', (string)($result['request_xml'] ?? ''));
    @file_put_contents(rtrim($debugDir, '/') . '/php_response.raw', (string)($result['raw'] ?? ''));
}

$out = [
    'status' => $result['status'] ?? null,
    'message_id' => $result['body']['MessageId'] ?? null,
    'fault' => $result['body']['Fault'] ?? null,
];
echo json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;

