<?php
declare(strict_types=1);

spl_autoload_register(static function (string $class): void {
    $prefix = 'LatvianEinvoice\\';
    $baseDir = __DIR__ . '/../src/';
    if (strncmp($prefix, $class, strlen($prefix)) !== 0) return;
    require_once $baseDir . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
});

use LatvianEinvoice\Client;
use LatvianEinvoice\Config;
use LatvianEinvoice\Attachment;

$wsdlUrl        = getenv('DIV_WSDL_URL') ?: 'https://divtest.vraa.gov.lv/Vraa.Div.WebService.UnifiedInterface/UnifiedService.svc?wsdl';
$clientCertPath = getenv('DIV_CLIENT_CERT') ?: '';
$clientKeyPath  = getenv('DIV_CLIENT_KEY') ?: '';
$sender         = (string)(getenv('DIV_SENDER') ?: '');
$recipient      = (string)(getenv('DIV_RECIPIENT') ?: $sender);
$vidRecipient   = 'VID_EREKINI_TEST@90000069281'; // VID TEST sub-address (PROD: VID_EREKINI_PROD@90000069281)

if ($sender === '') {
    fwrite(STDERR, "Error: DIV_SENDER env var is required.\n");
    exit(1);
}

$cfg = new Config(
    $wsdlUrl,
    clientCertPath:  $clientCertPath !== '' ? $clientCertPath : null,
    clientKeyPath:   $clientKeyPath  !== '' ? $clientKeyPath  : null,
    certificatePath: $clientCertPath !== '' ? $clientCertPath : null,
    privateKeyPath:  $clientKeyPath  !== '' ? $clientKeyPath  : null,
    verifySsl: false,
    defaultFrom: $sender,
);

// Derive registration number from sender e-address (e.g. _PRIVATE@40001234567 -> 40001234567)
$senderRegNo = preg_replace('/^[^@]+@/', '', $sender);
$issueDate   = date('Y-m-d');

// Minimal BIS3 UBL invoice XML
$invoiceId = 'PHP-EINV-' . substr(uniqid(), -6);
$invoiceXml = <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"
         xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2">
  <cbc:CustomizationID>urn:cen.eu:en16931:2017#compliant#urn:fdc:peppol.eu:2017:poacc:billing:3.0</cbc:CustomizationID>
  <cbc:ProfileID>urn:fdc:peppol.eu:2017:poacc:billing:01:1.0</cbc:ProfileID>
  <cbc:ID>$invoiceId</cbc:ID>
  <cbc:IssueDate>{$issueDate}</cbc:IssueDate>
  <cbc:InvoiceTypeCode>380</cbc:InvoiceTypeCode>
  <cbc:DocumentCurrencyCode>EUR</cbc:DocumentCurrencyCode>
  <cac:AccountingSupplierParty><cac:Party><cac:PartyName><cbc:Name>Test Sender</cbc:Name></cac:PartyName><cac:PostalAddress><cac:Country><cbc:IdentificationCode>LV</cbc:IdentificationCode></cac:Country></cac:PostalAddress><cac:PartyLegalEntity><cbc:RegistrationName>Test Sender</cbc:RegistrationName><cbc:CompanyID>$senderRegNo</cbc:CompanyID></cac:PartyLegalEntity></cac:Party></cac:AccountingSupplierParty>
  <cac:AccountingCustomerParty><cac:Party><cac:PartyName><cbc:Name>Test Recipient</cbc:Name></cac:PartyName><cac:PostalAddress><cac:Country><cbc:IdentificationCode>LV</cbc:IdentificationCode></cac:Country></cac:PostalAddress><cac:PartyLegalEntity><cbc:RegistrationName>Test Recipient</cbc:RegistrationName><cbc:CompanyID>$senderRegNo</cbc:CompanyID></cac:PartyLegalEntity></cac:Party></cac:AccountingCustomerParty>
  <cac:LegalMonetaryTotal><cbc:LineExtensionAmount currencyID="EUR">100.00</cbc:LineExtensionAmount><cbc:TaxExclusiveAmount currencyID="EUR">100.00</cbc:TaxExclusiveAmount><cbc:TaxInclusiveAmount currencyID="EUR">121.00</cbc:TaxInclusiveAmount><cbc:PayableAmount currencyID="EUR">121.00</cbc:PayableAmount></cac:LegalMonetaryTotal>
  <cac:InvoiceLine><cbc:ID>1</cbc:ID><cbc:InvoicedQuantity unitCode="C62">1</cbc:InvoicedQuantity><cbc:LineExtensionAmount currencyID="EUR">100.00</cbc:LineExtensionAmount><cac:Item><cbc:Name>Test item</cbc:Name></cac:Item><cac:Price><cbc:PriceAmount currencyID="EUR">100.00</cbc:PriceAmount></cac:Price></cac:InvoiceLine>
</Invoice>
XML;

// Client::sendMessage with documentKindCode='EINVOICE' auto-fetches GetPublicKeyList for all
// recipients and builds per-recipient EncryptionInfo (oaep_cbc mode). No manual key handling needed.
$client = new Client($cfg);
$result = $client->sendMessage(
    [$recipient, $vidRecipient],
    'EINVOICE',
    'PHP EINVOICE test ' . $invoiceId,
    'Please see attached e-invoice.',
    [new Attachment('invoice.xml', $invoiceXml, 'application/xml')]
);

$debugDir = getenv('DIV_DEBUG_DIR') ?: '';
if ($debugDir !== '' && isset($result['request_xml'])) {
    @mkdir($debugDir, 0777, true);
    @file_put_contents(rtrim($debugDir, '/') . '/php_einvoice_capture.xml', (string)$result['request_xml']);
}

echo json_encode([
    'status'     => $result['status'],
    'message_id' => $result['body']['MessageId'] ?? null,
    'fault'      => $result['body']['Fault'] ?? null,
    'invoice_id' => $invoiceId,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
