<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/SidecarClient.php';

use LatvianEinvoice\SidecarClient;

$baseUrl = getenv('DIV_SIDECAR_URL') ?: 'http://127.0.0.1:18080';
$connectionId = getenv('DIV_CONNECTION_ID') ?: 'P40103166694_01';
$recipient = getenv('DIV_RECIPIENT') ?: '_GATIS@90001733697';

$subject = 'PHP smoke test ' . gmdate('Y-m-d\\TH:i:s\\Z');

$client = new SidecarClient($baseUrl);
$result = $client->sendTextMessage(
    $connectionId,
    $recipient,
    $subject,
    'Hello from PHP sidecar',
    false
);

echo json_encode($result, JSON_PRETTY_PRINT) . PHP_EOL;
