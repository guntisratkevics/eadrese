<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use LatvianEinvoice\Client;
use LatvianEinvoice\Config;

$wsdlUrl = getenv('DIV_WSDL_URL') ?: 'https://divtest.vraa.gov.lv/Vraa.Div.WebService.UnifiedInterface/UnifiedService.svc?wsdl';

$clientCertPath = getenv('DIV_CLIENT_CERT') ?: '';
$clientKeyPath = getenv('DIV_CLIENT_KEY') ?: '';
$signCertPath = getenv('DIV_SIGN_CERT') ?: $clientCertPath;
$signKeyPath = getenv('DIV_SIGN_KEY') ?: $clientKeyPath;

$sender = getenv('DIV_SENDER') ?: '_PRIVATE@<REG_NO>';
$recipient = getenv('DIV_RECIPIENT') ?: '_PRIVATE@<RECIPIENT_REG_NO>';

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

$subject = 'PHP SOAP smoke ' . gmdate('Y-m-d\\TH:i:s\\Z');
$result = $client->sendTextMessageSoap([$recipient], $subject, 'Hello from PHP SOAP');

echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;

