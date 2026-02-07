<?php

declare(strict_types=1);

namespace LatvianEinvoice\Soap;

use LatvianEinvoice\Config;

final class DirectSoapClient
{
    private const NS_SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    private const NS_UUI = 'http://vraa.gov.lv/xmlschemas/div/uui/2011/11';
    private const NS_DIV = 'http://ivis.eps.gov.lv/XMLSchemas/100001/DIV/v1-0';

    private const ACTION_SEND_MESSAGE = 'http://vraa.gov.lv/div/uui/2011/11/UnifiedServiceInterface/SendMessage';

    private Config $cfg;

    public function __construct(Config $cfg)
    {
        $this->cfg = $cfg;
    }

    /**
     * @param string[] $recipients
     * @return array{status:int, body:array|null, raw:string, request_xml:string, message_id:string}
     */
    public function sendTextMessage(
        array $recipients,
        string $subject,
        string $bodyText = '',
        string $documentKindCode = 'DOC_EMPTY',
        bool $notifySenderOnDelivery = true,
        ?string $traceText = 'Created'
    ): array {
        $endpoint = $this->endpointFromWsdl($this->cfg->wsdlUrl);
        $doc = new \DOMDocument('1.0', 'utf-8');
        $doc->formatOutput = false;
        $doc->preserveWhiteSpace = false;

        $env = $doc->createElementNS(self::NS_SOAP, 'soap-env:Envelope');
        $doc->appendChild($env);
        $header = $doc->createElementNS(self::NS_SOAP, 'soap-env:Header');
        $body = $doc->createElementNS(self::NS_SOAP, 'soap-env:Body');
        $env->appendChild($header);
        $env->appendChild($body);

        $sendInput = $doc->createElementNS(self::NS_UUI, 'SendMessageInput');
        $body->appendChild($sendInput);

        $divEnv = $doc->createElementNS(self::NS_DIV, 'Envelope');
        $sendInput->appendChild($divEnv);

        $messageId = bin2hex(random_bytes(16));
        $senderAddr = $this->cfg->defaultFrom;

        $senderDoc = $doc->createElementNS(self::NS_DIV, 'SenderDocument');
        $senderDoc->setAttribute('Id', 'SenderSection');
        $divEnv->appendChild($senderDoc);

        $docMeta = $doc->createElementNS(self::NS_DIV, 'DocumentMetadata');
        $senderDoc->appendChild($docMeta);
        $general = $doc->createElementNS(self::NS_DIV, 'GeneralMetadata');
        $docMeta->appendChild($general);

        $authors = $doc->createElementNS(self::NS_DIV, 'Authors');
        $authorEntry = $doc->createElementNS(self::NS_DIV, 'AuthorEntry');
        $institution = $doc->createElementNS(self::NS_DIV, 'Institution');
        $title = $doc->createElementNS(self::NS_DIV, 'Title', $senderAddr);
        $institution->appendChild($title);
        $authorEntry->appendChild($institution);
        $authors->appendChild($authorEntry);
        $general->appendChild($authors);

        $now = new \DateTimeImmutable('now', new \DateTimeZone('Europe/Riga'));
        $general->appendChild($doc->createElementNS(self::NS_DIV, 'Date', $now->format('Y-m-d')));

        $docKind = $doc->createElementNS(self::NS_DIV, 'DocumentKind');
        $docKind->appendChild($doc->createElementNS(self::NS_DIV, 'DocumentKindCode', $documentKindCode));
        $docKind->appendChild($doc->createElementNS(self::NS_DIV, 'DocumentKindVersion', '1.0'));
        if ($documentKindCode !== 'DOC_EMPTY') {
            $docKind->appendChild($doc->createElementNS(self::NS_DIV, 'DocumentKindName', $documentKindCode));
        }
        $general->appendChild($docKind);

        $general->appendChild($doc->createElementNS(self::NS_DIV, 'Description', $bodyText));
        $general->appendChild($doc->createElementNS(self::NS_DIV, 'Title', $subject));

        $senderTransport = $doc->createElementNS(self::NS_DIV, 'SenderTransportMetadata');
        $senderTransport->appendChild($doc->createElementNS(self::NS_DIV, 'SenderE-Address', $senderAddr));
        $senderTransport->appendChild($doc->createElementNS(self::NS_DIV, 'SenderRefNumber', $messageId));

        $recipientsEl = $doc->createElementNS(self::NS_DIV, 'Recipients');
        foreach ($recipients as $recipient) {
            $entry = $doc->createElementNS(self::NS_DIV, 'RecipientEntry');
            $entry->appendChild($doc->createElementNS(self::NS_DIV, 'RecipientE-Address', $recipient));
            $recipientsEl->appendChild($entry);
        }
        $senderTransport->appendChild($recipientsEl);

        $senderTransport->appendChild(
            $doc->createElementNS(self::NS_DIV, 'NotifySenderOnDelivery', $notifySenderOnDelivery ? 'true' : 'false')
        );
        $senderTransport->appendChild($doc->createElementNS(self::NS_DIV, 'Priority', 'normal'));

        if ($traceText) {
            $trace = $doc->createElementNS(self::NS_DIV, 'TraceInfo');
            $traceEntry = $doc->createElementNS(self::NS_DIV, 'TraceInfoEntry');
            $traceEntry->appendChild($doc->createElementNS(self::NS_DIV, 'TraceInfoID', 'Trace1'));
            $traceEntry->appendChild($doc->createElementNS(self::NS_DIV, 'TraceText', substr($traceText, 0, 50)));
            $trace->appendChild($traceEntry);
            $senderTransport->appendChild($trace);
        }

        $senderDoc->appendChild($senderTransport);

        $divEnv->appendChild($doc->createElementNS(self::NS_DIV, 'Signatures'));

        // Sign the DIV envelope first, then apply WSSE (matches Python sidecar flow).
        DivEnvelopeSigner::signEnvelope($doc, $divEnv, $this->cfg);
        WsseSigner::apply($doc, $header, $this->cfg, $endpoint, self::ACTION_SEND_MESSAGE);

        $requestXml = $doc->saveXML();
        if ($requestXml === false) {
            throw new \RuntimeException('Failed to serialize SOAP XML');
        }

        [$status, $raw] = $this->postSoap($endpoint, $requestXml);
        $decoded = self::tryParseSoapResponse($raw);
        return [
            'status' => $status,
            'body' => $decoded,
            'raw' => $raw,
            'request_xml' => $requestXml,
            'message_id' => $messageId,
        ];
    }

    private function endpointFromWsdl(string $wsdlUrl): string
    {
        if (str_ends_with(strtolower($wsdlUrl), '?wsdl')) {
            return substr($wsdlUrl, 0, -5);
        }
        return $wsdlUrl;
    }

    /**
     * @return array{0:int,1:string}
     */
    private function postSoap(string $endpoint, string $requestXml): array
    {
        $ch = curl_init($endpoint);
        if ($ch === false) {
            throw new \RuntimeException('Failed to init cURL');
        }

        $headers = [
            'Content-Type: application/soap+xml; charset=utf-8',
            'Accept: application/soap+xml, text/xml',
        ];

        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $requestXml);

        if ($this->cfg->clientCertPath) {
            curl_setopt($ch, CURLOPT_SSLCERT, $this->cfg->clientCertPath);
        }
        if ($this->cfg->clientKeyPath) {
            curl_setopt($ch, CURLOPT_SSLKEY, $this->cfg->clientKeyPath);
        }
        if (!$this->cfg->verifySsl) {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        }

        $raw = curl_exec($ch);
        if ($raw === false) {
            $err = curl_error($ch);
            curl_close($ch);
            throw new \RuntimeException('cURL error: ' . $err);
        }
        $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        return [$status, (string)$raw];
    }

    /**
     * @return array<string,mixed>|null
     */
    private static function tryParseSoapResponse(string $raw): ?array
    {
        $raw = trim($raw);
        if ($raw === '') {
            return null;
        }
        $doc = new \DOMDocument();
        $doc->preserveWhiteSpace = false;
        $doc->formatOutput = false;
        if (!@$doc->loadXML($raw)) {
            return null;
        }
        $xpath = new \DOMXPath($doc);
        // Grab the first MessageId/MessageID value if present.
        $nodes = $xpath->query('//*[local-name()=\"MessageId\" or local-name()=\"MessageID\"]');
        $messageId = null;
        if ($nodes && $nodes->length > 0) {
            $messageId = trim((string)$nodes->item(0)->textContent);
        }
        if ($messageId) {
            return ['MessageId' => $messageId];
        }

        $fault = $xpath->query('//*[local-name()=\"Fault\"]');
        if ($fault && $fault->length > 0 && $fault->item(0) instanceof \DOMElement) {
            $faultEl = $fault->item(0);
            $code = trim((string)$xpath->evaluate('string(.//*[local-name()=\"Code\"]/*[local-name()=\"Value\"][1])', $faultEl));
            $reason = trim((string)$xpath->evaluate('string(.//*[local-name()=\"Reason\"]/*[local-name()=\"Text\"][1])', $faultEl));
            $detail = trim((string)$xpath->evaluate('string(.//*[local-name()=\"Detail\"][1])', $faultEl));
            return [
                'Fault' => [
                    'Code' => $code !== '' ? $code : null,
                    'Reason' => $reason !== '' ? $reason : null,
                    'Detail' => $detail !== '' ? $detail : null,
                ],
            ];
        }

        return null;
    }
}
