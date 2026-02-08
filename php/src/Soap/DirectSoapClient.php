<?php

declare(strict_types=1);

namespace LatvianEinvoice\Soap;

use LatvianEinvoice\Config;

final class DirectSoapClient
{
    private const NS_SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    private const NS_UUI = 'http://vraa.gov.lv/xmlschemas/div/uui/2011/11';
    private const NS_DIV = 'http://ivis.eps.gov.lv/XMLSchemas/100001/DIV/v1-0';
    private const NS_ADDR = 'http://ivis.eps.gov.lv/XMLSchemas/100001/Address/v1-1';
    private const NS_DS = 'http://www.w3.org/2000/09/xmldsig#';

    private const ACTION_SEND_MESSAGE = 'http://vraa.gov.lv/div/uui/2011/11/UnifiedServiceInterface/SendMessage';
    private const ACTION_GET_MESSAGE_LIST = 'http://vraa.gov.lv/div/uui/2011/11/UnifiedServiceInterface/GetMessageList';
    private const ACTION_GET_MESSAGE = 'http://vraa.gov.lv/div/uui/2011/11/UnifiedServiceInterface/GetMessage';
    private const ACTION_GET_ATTACHMENT_SECTION = 'http://vraa.gov.lv/div/uui/2011/11/UnifiedServiceInterface/GetAttachmentSection';
    private const ACTION_CONFIRM_MESSAGE = 'http://vraa.gov.lv/div/uui/2011/11/UnifiedServiceInterface/ConfirmMessage';

    private Config $cfg;

    public function __construct(Config $cfg)
    {
        $this->cfg = $cfg;
    }

    /**
     * @return array{status:int, body:array|null, raw:string, request_xml:string, message_id:string}
     */
    public function sendEnvelopeXml(string $divEnvelopeXml): array
    {
        $endpoint = $this->endpointFromWsdl($this->cfg->wsdlUrl);
        $divEnvelopeXml = self::stripXmlDeclaration($divEnvelopeXml);
        $requestXml = $this->buildSoapRequestXml($endpoint, $divEnvelopeXml);

        [$status, $raw] = $this->postSoap($endpoint, $requestXml);
        $decoded = self::tryParseSoapResponse($raw);
        return [
            'status' => $status,
            'body' => $decoded,
            'raw' => $raw,
            'request_xml' => $requestXml,
            'message_id' => bin2hex(random_bytes(16)),
        ];
    }

    /**
     * Direct SOAP GetMessageList (mTLS + WSSE).
     *
     * @return array{status:int, body:array|null, raw:string, request_xml:string}
     */
    public function getMessageList(int $maxResultCount = 10, ?int $addresseeUnitId = null): array
    {
        $endpoint = $this->endpointFromWsdl($this->cfg->wsdlUrl);

        $doc = new \DOMDocument('1.0', 'utf-8');
        $doc->formatOutput = false;
        $doc->preserveWhiteSpace = false;

        $env = $doc->createElementNS(self::NS_SOAP, 'Envelope');
        $doc->appendChild($env);
        $header = $doc->createElementNS(self::NS_SOAP, 'Header');
        $body = $doc->createElementNS(self::NS_SOAP, 'Body');
        $env->appendChild($header);
        $env->appendChild($body);

        $input = $doc->createElementNS(self::NS_UUI, 'GetMessageListInput');
        if ($maxResultCount > 0) {
            $input->appendChild($doc->createElementNS(self::NS_UUI, 'MaxResultCount', (string)$maxResultCount));
        }
        if ($addresseeUnitId !== null) {
            $input->appendChild($doc->createElementNS(self::NS_UUI, 'AddresseeUnitId', (string)$addresseeUnitId));
        }
        $body->appendChild($input);

        WsseSigner::apply($doc, $header, $this->cfg, $endpoint, self::ACTION_GET_MESSAGE_LIST);

        $requestXml = $doc->saveXML();
        if ($requestXml === false) {
            throw new \RuntimeException('Failed to serialize SOAP XML');
        }

        [$status, $raw] = $this->postSoap($endpoint, $requestXml);

        $faultOrNull = self::tryParseSoapResponse($raw);
        if (is_array($faultOrNull) && array_key_exists('Fault', $faultOrNull)) {
            return [
                'status' => $status,
                'body' => $faultOrNull,
                'raw' => $raw,
                'request_xml' => $requestXml,
            ];
        }

        $parsed = self::tryParseGetMessageListResponse($raw);
        return [
            'status' => $status,
            'body' => $parsed,
            'raw' => $raw,
            'request_xml' => $requestXml,
        ];
    }

    /**
     * Direct SOAP GetMessage (mTLS + WSSE).
     *
     * @return array{status:int, body:array|null, raw:string, request_xml:string}
     */
    public function getMessage(string $messageId): array
    {
        $endpoint = $this->endpointFromWsdl($this->cfg->wsdlUrl);

        $doc = new \DOMDocument('1.0', 'utf-8');
        $doc->formatOutput = false;
        $doc->preserveWhiteSpace = false;

        $env = $doc->createElementNS(self::NS_SOAP, 'Envelope');
        $doc->appendChild($env);
        $header = $doc->createElementNS(self::NS_SOAP, 'Header');
        $body = $doc->createElementNS(self::NS_SOAP, 'Body');
        $env->appendChild($header);
        $env->appendChild($body);

        $input = $doc->createElementNS(self::NS_UUI, 'GetMessageInput');
        $input->appendChild($doc->createElementNS(self::NS_UUI, 'MessageId', $messageId));
        $body->appendChild($input);

        WsseSigner::apply($doc, $header, $this->cfg, $endpoint, self::ACTION_GET_MESSAGE);

        $requestXml = $doc->saveXML();
        if ($requestXml === false) {
            throw new \RuntimeException('Failed to serialize SOAP XML');
        }

        [$status, $raw] = $this->postSoap($endpoint, $requestXml);

        $faultOrNull = self::tryParseSoapResponse($raw);
        if (is_array($faultOrNull) && array_key_exists('Fault', $faultOrNull)) {
            return [
                'status' => $status,
                'body' => $faultOrNull,
                'raw' => $raw,
                'request_xml' => $requestXml,
            ];
        }

        $parsed = self::tryParseGetMessageResponse($raw);
        return [
            'status' => $status,
            'body' => $parsed,
            'raw' => $raw,
            'request_xml' => $requestXml,
        ];
    }

    /**
     * Direct SOAP GetAttachmentSection (mTLS + WSSE).
     *
     * @return array{status:int, body:array|null, raw:string, request_xml:string}
     */
    public function getAttachmentSection(string $messageId, string $contentId, int $sectionIndex): array
    {
        $endpoint = $this->endpointFromWsdl($this->cfg->wsdlUrl);

        $doc = new \DOMDocument('1.0', 'utf-8');
        $doc->formatOutput = false;
        $doc->preserveWhiteSpace = false;

        $env = $doc->createElementNS(self::NS_SOAP, 'Envelope');
        $doc->appendChild($env);
        $header = $doc->createElementNS(self::NS_SOAP, 'Header');
        $body = $doc->createElementNS(self::NS_SOAP, 'Body');
        $env->appendChild($header);
        $env->appendChild($body);

        $input = $doc->createElementNS(self::NS_UUI, 'GetAttachmentSectionInput');
        $input->appendChild($doc->createElementNS(self::NS_UUI, 'MessageId', $messageId));
        $input->appendChild($doc->createElementNS(self::NS_UUI, 'ContentId', $contentId));
        $input->appendChild($doc->createElementNS(self::NS_UUI, 'SectionIndex', (string)$sectionIndex));
        $body->appendChild($input);

        WsseSigner::apply($doc, $header, $this->cfg, $endpoint, self::ACTION_GET_ATTACHMENT_SECTION);

        $requestXml = $doc->saveXML();
        if ($requestXml === false) {
            throw new \RuntimeException('Failed to serialize SOAP XML');
        }

        [$status, $raw] = $this->postSoap($endpoint, $requestXml);

        $faultOrNull = self::tryParseSoapResponse($raw);
        if (is_array($faultOrNull) && array_key_exists('Fault', $faultOrNull)) {
            return [
                'status' => $status,
                'body' => $faultOrNull,
                'raw' => $raw,
                'request_xml' => $requestXml,
            ];
        }

        $parsed = self::tryParseGetAttachmentSectionResponse($raw);
        return [
            'status' => $status,
            'body' => $parsed,
            'raw' => $raw,
            'request_xml' => $requestXml,
        ];
    }

    /**
     * Direct SOAP ConfirmMessage (mTLS + WSSE + DIV combined envelope signing).
     *
     * @param string[]|null $recipientEaddresses
     * @return array{status:int, body:array|null, raw:string, request_xml:string}
     */
    public function confirmMessage(
        string $messageId,
        string $status = 'RecipientAccepted',
        ?string $statusCode = null,
        ?string $statusReason = null,
        ?array $recipientEaddresses = null
    ): array {
        $endpoint = $this->endpointFromWsdl($this->cfg->wsdlUrl);

        // Fetch message to obtain ConfirmationName + recipients and the message envelope parts (Sender/Server sections).
        $msg = $this->getMessage($messageId);
        $msgBody = is_array($msg['body'] ?? null) ? $msg['body'] : null;
        if (!$msgBody || isset($msgBody['Fault'])) {
            return [
                'status' => (int)($msg['status'] ?? 0),
                'body' => $msgBody,
                'raw' => (string)($msg['raw'] ?? ''),
                'request_xml' => (string)($msg['request_xml'] ?? ''),
            ];
        }

        $envelopeXml = $msgBody['EnvelopeXml'] ?? null;
        if (!is_string($envelopeXml) || trim($envelopeXml) === '') {
            throw new \RuntimeException('GetMessage did not include EnvelopeXml');
        }

        $recipients = $recipientEaddresses;
        if ($recipients === null) {
            $recipients = is_array($msgBody['Recipients'] ?? null) ? $msgBody['Recipients'] : [];
        }
        if (!$recipients) {
            $fallback = trim((string)($this->cfg->defaultFrom ?? ''));
            $recipients = $fallback !== '' ? [$fallback] : [];
        }

        $confirmationName = is_string($msgBody['ConfirmationName'] ?? null) ? (string)$msgBody['ConfirmationName'] : '';
        $nowTs = (string)time();
        $entryId = $confirmationName !== '' ? $confirmationName . 'RecipientSection' : ('RecipientConfirmation-' . $nowTs);
        $signatureId = $confirmationName !== '' ? $confirmationName . 'RecipientSignature' : ('RecipientSignature-' . $nowTs);

        // Build RecipientConfirmationPart (what we will send).
        $partDoc = new \DOMDocument('1.0', 'utf-8');
        $partDoc->formatOutput = false;
        $partDoc->preserveWhiteSpace = false;
        $partRoot = $partDoc->createElementNS(self::NS_DIV, 'RecipientConfirmationPart');
        $partDoc->appendChild($partRoot);
        $confirmations = $partDoc->createElementNS(self::NS_DIV, 'RecipientConfirmations');
        $partRoot->appendChild($confirmations);
        $entry = $partDoc->createElementNS(self::NS_DIV, 'ConfirmationEntry');
        $entry->setAttribute('Id', $entryId);
        $confirmations->appendChild($entry);
        $related = $partDoc->createElementNS(self::NS_DIV, 'RelatedRecipients');
        $entry->appendChild($related);
        foreach ($recipients as $addr) {
            $addr = trim((string)$addr);
            if ($addr === '') {
                continue;
            }
            $related->appendChild($partDoc->createElementNS(self::NS_DIV, 'E-Address', $addr));
        }
        $entry->appendChild($partDoc->createElementNS(self::NS_DIV, 'Status', $status));
        if ($statusCode !== null && trim($statusCode) !== '') {
            $entry->appendChild($partDoc->createElementNS(self::NS_DIV, 'StatusCode', (string)$statusCode));
        }
        if ($statusReason !== null && trim($statusReason) !== '') {
            $entry->appendChild($partDoc->createElementNS(self::NS_DIV, 'StatusReason', (string)$statusReason));
        }

        // Parse the message Envelope XML to extract SenderDocument and ServerTransportMetadata.
        $envDoc = new \DOMDocument('1.0', 'utf-8');
        $envDoc->preserveWhiteSpace = false;
        $envDoc->formatOutput = false;
        if (!@$envDoc->loadXML($envelopeXml)) {
            throw new \RuntimeException('Failed to parse EnvelopeXml from GetMessage');
        }
        $envXpath = new \DOMXPath($envDoc);
        $senderDocEl = $envXpath->query('//*[local-name()="SenderDocument"][1]')?->item(0);
        $serverMetaEl = $envXpath->query('//*[local-name()="ServerTransportMetadata"][1]')?->item(0);
        if (!$senderDocEl instanceof \DOMElement || !$serverMetaEl instanceof \DOMElement) {
            throw new \RuntimeException('EnvelopeXml missing SenderDocument or ServerTransportMetadata');
        }

        // Build combined envelope for signing (Java/.NET style): SenderSection + ServerSection + RecipientSection.
        $combinedDoc = new \DOMDocument('1.0', 'utf-8');
        $combinedDoc->formatOutput = false;
        $combinedDoc->preserveWhiteSpace = false;
        $combinedRoot = $combinedDoc->createElementNS(self::NS_DIV, 'RecipientConfirmationPart');
        $combinedDoc->appendChild($combinedRoot);
        $combinedSender = $combinedDoc->importNode($senderDocEl, true);
        if ($combinedSender instanceof \DOMElement && $combinedSender->getAttribute('Id') === '') {
            $combinedSender->setAttribute('Id', 'SenderSection');
        }
        $combinedRoot->appendChild($combinedSender);
        $combinedServer = $combinedDoc->importNode($serverMetaEl, true);
        if ($combinedServer instanceof \DOMElement && $combinedServer->getAttribute('Id') === '') {
            $combinedServer->setAttribute('Id', 'ServerSection');
        }
        $combinedRoot->appendChild($combinedServer);
        $combinedConfirmations = $combinedDoc->createElementNS(self::NS_DIV, 'RecipientConfirmations');
        $combinedRoot->appendChild($combinedConfirmations);
        $combinedConfirmations->appendChild($combinedDoc->importNode($entry, true));
        $combinedRoot->appendChild($combinedDoc->createElementNS(self::NS_DIV, 'Signatures'));

        // Apply the Java "netify" XSLT to normalize prefixes/namespace scoping before signing.
        $netifiedRoot = DivNetify::netifyElement($combinedRoot);
        $netDoc = $netifiedRoot->ownerDocument;
        if (!$netDoc instanceof \DOMDocument) {
            throw new \RuntimeException('Netify failed to produce a DOMDocument');
        }

        // Sign the combined document and copy the resulting ds:Signature into the part that is sent.
        $signatureEl = DivEnvelopeSigner::signCombinedEnvelope(
            $netDoc,
            $netifiedRoot,
            $this->cfg,
            $signatureId,
            ['SenderSection', 'ServerSection', $entryId]
        );
        $signatures = $partDoc->createElementNS(self::NS_DIV, 'Signatures');
        $partRoot->appendChild($signatures);
        $signatures->appendChild($partDoc->importNode($signatureEl, true));

        $partXml = $partDoc->saveXML($partRoot);
        if ($partXml === false) {
            throw new \RuntimeException('Failed to serialize RecipientConfirmationPart XML');
        }

        // Build the SOAP ConfirmMessage request and inject the RecipientConfirmationPart verbatim.
        $soapDoc = new \DOMDocument('1.0', 'utf-8');
        $soapDoc->formatOutput = false;
        $soapDoc->preserveWhiteSpace = false;
        $soapEnv = $soapDoc->createElementNS(self::NS_SOAP, 'Envelope');
        $soapDoc->appendChild($soapEnv);
        $soapHeader = $soapDoc->createElementNS(self::NS_SOAP, 'Header');
        $soapBody = $soapDoc->createElementNS(self::NS_SOAP, 'Body');
        $soapEnv->appendChild($soapHeader);
        $soapEnv->appendChild($soapBody);

        $input = $soapDoc->createElementNS(self::NS_UUI, 'ConfirmMessageInput');
        $input->appendChild($soapDoc->createComment('DIV_CONFIRMATION_PART_PLACEHOLDER'));
        $input->appendChild($soapDoc->createElementNS(self::NS_UUI, 'MessageId', $messageId));
        $soapBody->appendChild($input);

        WsseSigner::apply($soapDoc, $soapHeader, $this->cfg, $endpoint, self::ACTION_CONFIRM_MESSAGE);
        $requestXml = $soapDoc->saveXML();
        if ($requestXml === false) {
            throw new \RuntimeException('Failed to serialize SOAP XML');
        }
        $replaceCount = 0;
        $requestXml = str_replace('<!--DIV_CONFIRMATION_PART_PLACEHOLDER-->', $partXml, $requestXml, $replaceCount);
        if ($replaceCount !== 1) {
            throw new \RuntimeException('Failed to inject RecipientConfirmationPart into SOAP XML');
        }

        [$status, $raw] = $this->postSoap($endpoint, $requestXml);
        $faultOrNull = self::tryParseSoapResponse($raw);
        if (is_array($faultOrNull) && array_key_exists('Fault', $faultOrNull)) {
            return [
                'status' => $status,
                'body' => $faultOrNull,
                'raw' => $raw,
                'request_xml' => $requestXml,
            ];
        }

        return [
            'status' => $status,
            'body' => null,
            'raw' => $raw,
            'request_xml' => $requestXml,
        ];
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
        ?string $traceText = null
    ): array {
        $endpoint = $this->endpointFromWsdl($this->cfg->wsdlUrl);

        $messageId = bin2hex(random_bytes(16));
        $senderAddr = $this->cfg->defaultFrom;

        // Build the DIV Envelope in a standalone DOM to avoid inheriting SOAP namespaces.
        // DIV validates the extracted Envelope XML, so signature canonicalization must match a standalone document.
        $divDoc = new \DOMDocument('1.0', 'utf-8');
        $divDoc->formatOutput = false;
        $divDoc->preserveWhiteSpace = false;

        $divEnv = $divDoc->createElementNS(self::NS_DIV, 'Envelope');
        // Match the official clients: declare these namespaces on the DIV root.
        $divEnv->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:addr', self::NS_ADDR);
        $divEnv->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:ds', self::NS_DS);
        $divDoc->appendChild($divEnv);

        $senderDoc = $divDoc->createElementNS(self::NS_DIV, 'SenderDocument');
        $senderDoc->setAttribute('Id', 'SenderSection');
        $divEnv->appendChild($senderDoc);

        $docMeta = $divDoc->createElementNS(self::NS_DIV, 'DocumentMetadata');
        $senderDoc->appendChild($docMeta);
        $general = $divDoc->createElementNS(self::NS_DIV, 'GeneralMetadata');
        $docMeta->appendChild($general);

        $authors = $divDoc->createElementNS(self::NS_DIV, 'Authors');
        $authorEntry = $divDoc->createElementNS(self::NS_DIV, 'AuthorEntry');
        $institution = $divDoc->createElementNS(self::NS_DIV, 'Institution');
        $title = $divDoc->createElementNS(self::NS_DIV, 'Title', $senderAddr);
        $institution->appendChild($title);
        $authorEntry->appendChild($institution);
        $authors->appendChild($authorEntry);
        $general->appendChild($authors);

        $now = new \DateTimeImmutable('now', new \DateTimeZone('Europe/Riga'));
        $general->appendChild($divDoc->createElementNS(self::NS_DIV, 'Date', $now->format('Y-m-d')));

        $docKind = $divDoc->createElementNS(self::NS_DIV, 'DocumentKind');
        $docKind->appendChild($divDoc->createElementNS(self::NS_DIV, 'DocumentKindCode', $documentKindCode));
        $docKind->appendChild($divDoc->createElementNS(self::NS_DIV, 'DocumentKindVersion', '1.0'));
        if ($documentKindCode !== 'DOC_EMPTY') {
            $docKind->appendChild($divDoc->createElementNS(self::NS_DIV, 'DocumentKindName', $documentKindCode));
        }
        $general->appendChild($docKind);

        $general->appendChild($divDoc->createElementNS(self::NS_DIV, 'Description', $bodyText));
        $general->appendChild($divDoc->createElementNS(self::NS_DIV, 'Title', $subject));

        $senderTransport = $divDoc->createElementNS(self::NS_DIV, 'SenderTransportMetadata');
        $senderTransport->appendChild($divDoc->createElementNS(self::NS_DIV, 'SenderE-Address', $senderAddr));
        $senderTransport->appendChild($divDoc->createElementNS(self::NS_DIV, 'SenderRefNumber', $messageId));

        $recipientsEl = $divDoc->createElementNS(self::NS_DIV, 'Recipients');
        foreach ($recipients as $recipient) {
            $entry = $divDoc->createElementNS(self::NS_DIV, 'RecipientEntry');
            $entry->appendChild($divDoc->createElementNS(self::NS_DIV, 'RecipientE-Address', $recipient));
            $recipientsEl->appendChild($entry);
        }
        $senderTransport->appendChild($recipientsEl);

        $senderTransport->appendChild(
            $divDoc->createElementNS(self::NS_DIV, 'NotifySenderOnDelivery', $notifySenderOnDelivery ? 'true' : 'false')
        );
        $senderTransport->appendChild($divDoc->createElementNS(self::NS_DIV, 'Priority', 'normal'));

        if ($traceText) {
            $trace = $divDoc->createElementNS(self::NS_DIV, 'TraceInfo');
            $traceEntry = $divDoc->createElementNS(self::NS_DIV, 'TraceInfoEntry');
            $traceEntry->appendChild($divDoc->createElementNS(self::NS_DIV, 'TraceInfoID', 'Trace1'));
            $traceEntry->appendChild($divDoc->createElementNS(self::NS_DIV, 'TraceText', substr($traceText, 0, 50)));
            $trace->appendChild($traceEntry);
            $senderTransport->appendChild($trace);
        }

        $senderDoc->appendChild($senderTransport);

        $divEnv->appendChild($divDoc->createElementNS(self::NS_DIV, 'Signatures'));

        // Sign the DIV envelope first, then import into SOAP and apply WSSE.
        DivEnvelopeSigner::signEnvelope($divDoc, $divEnv, $this->cfg);

        // Serialize the DIV envelope as exclusive C14N to avoid libxml namespace hoisting, which can break
        // canonicalization-dependent signatures on the DIV side.
        $divXml = $divEnv->C14N(true, false, null, ['ds', 'addr']);
        if ($divXml === false) {
            throw new \RuntimeException('Failed to serialize DIV Envelope (C14N)');
        }
        $requestXml = $this->buildSoapRequestXml($endpoint, $divXml);

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

    private function buildSoapRequestXml(string $endpoint, string $divEnvelopeXml): string
    {
        $doc = new \DOMDocument('1.0', 'utf-8');
        $doc->formatOutput = false;
        $doc->preserveWhiteSpace = false;

        // Use the SOAP namespace as the default namespace (no soap-env prefix) so it does not become
        // an in-scope prefix for the DIV signature canonicalization in the Body.
        $env = $doc->createElementNS(self::NS_SOAP, 'Envelope');
        $doc->appendChild($env);
        $header = $doc->createElementNS(self::NS_SOAP, 'Header');
        $body = $doc->createElementNS(self::NS_SOAP, 'Body');
        $env->appendChild($header);
        $env->appendChild($body);

        $sendInput = $doc->createElementNS(self::NS_UUI, 'SendMessageInput');
        $body->appendChild($sendInput);
        // Insert the DIV XML via string replacement after WSSE is applied, so the SOAP serializer cannot
        // rewrite namespace declarations inside the DIV envelope.
        $sendInput->appendChild($doc->createComment('DIV_ENVELOPE_PLACEHOLDER'));

        WsseSigner::apply($doc, $header, $this->cfg, $endpoint, self::ACTION_SEND_MESSAGE);

        $requestXml = $doc->saveXML();
        if ($requestXml === false) {
            throw new \RuntimeException('Failed to serialize SOAP XML');
        }
        $replaceCount = 0;
        $requestXml = str_replace('<!--DIV_ENVELOPE_PLACEHOLDER-->', $divEnvelopeXml, $requestXml, $replaceCount);
        if ($replaceCount !== 1) {
            throw new \RuntimeException('Failed to inject DIV Envelope into SOAP XML');
        }
        return $requestXml;
    }

    private static function stripXmlDeclaration(string $xml): string
    {
        $xml = ltrim($xml);
        // UTF-8 BOM
        $xml = preg_replace('/^\\xEF\\xBB\\xBF/', '', $xml) ?? $xml;
        $xml = preg_replace('/^<\\?xml[^>]*\\?>\\s*/', '', $xml) ?? $xml;
        return $xml;
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
        $raw = ltrim($raw);
        if ($raw === '') {
            return null;
        }

        $xml = self::extractSoapXml($raw);
        if ($xml === null) {
            return null;
        }

        $doc = new \DOMDocument();
        $doc->preserveWhiteSpace = false;
        $doc->formatOutput = false;
        if (!@$doc->loadXML($xml)) {
            return null;
        }
        $xpath = new \DOMXPath($doc);
        // Grab the first MessageId/MessageID value if present.
        $nodes = $xpath->query('//*[local-name()="MessageId" or local-name()="MessageID"]');
        $messageId = null;
        if ($nodes && $nodes->length > 0) {
            $messageId = trim((string)$nodes->item(0)->textContent);
        }
        if ($messageId) {
            return ['MessageId' => $messageId];
        }

        $fault = $xpath->query('//*[local-name()="Fault"]');
        if ($fault && $fault->length > 0 && $fault->item(0) instanceof \DOMElement) {
            $faultEl = $fault->item(0);
            $code = trim((string)$xpath->evaluate('string(.//*[local-name()="Code"]/*[local-name()="Value"][1])', $faultEl));
            $reason = trim((string)$xpath->evaluate('string(.//*[local-name()="Reason"]/*[local-name()="Text"][1])', $faultEl));
            $detail = trim((string)$xpath->evaluate('string(.//*[local-name()="Detail"][1])', $faultEl));
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

    private static function tryParseGetMessageListResponse(string $raw): ?array
    {
        $doc = self::loadSoapDom($raw);
        if (!$doc instanceof \DOMDocument) {
            return null;
        }
        $xpath = new \DOMXPath($doc);

        $headers = [];
        $nodes = $xpath->query('//*[local-name()="MessageHeader"]');
        if ($nodes) {
            foreach ($nodes as $node) {
                if (!$node instanceof \DOMElement) {
                    continue;
                }
                $headers[] = [
                    'MessageId' => trim((string)$xpath->evaluate('string(./*[local-name()="MessageId"][1])', $node)) ?: null,
                    'SenderEAddress' => trim((string)$xpath->evaluate('string(./*[local-name()="SenderEAddress"][1])', $node)) ?: null,
                    'IsDelivered' => trim((string)$xpath->evaluate('string(./*[local-name()="IsDelivered"][1])', $node)) ?: null,
                    'SentOn' => trim((string)$xpath->evaluate('string(./*[local-name()="SentOn"][1])', $node)) ?: null,
                ];
            }
        }

        $hasMoreRaw = trim((string)$xpath->evaluate('string(//*[local-name()="HasMoreData"][1])'));
        $hasMore = null;
        if ($hasMoreRaw === 'true') {
            $hasMore = true;
        } elseif ($hasMoreRaw === 'false') {
            $hasMore = false;
        }

        return [
            'MessageHeaders' => $headers,
            'HasMoreData' => $hasMore,
        ];
    }

    private static function tryParseGetMessageResponse(string $raw): ?array
    {
        [$soapXml, $parts] = self::extractSoapXmlAndParts($raw);
        if ($soapXml === null) {
            return null;
        }
        $doc = new \DOMDocument();
        $doc->preserveWhiteSpace = false;
        $doc->formatOutput = false;
        if (!@$doc->loadXML($soapXml)) {
            return null;
        }
        $xpath = new \DOMXPath($doc);

        $envEl = $xpath->query('//*[local-name()="GetMessageOutput"]//*[local-name()="Envelope"][1]');
        $envelopeXml = null;
        if ($envEl && $envEl->length > 0 && $envEl->item(0) instanceof \DOMElement) {
            $envelopeXml = $doc->saveXML($envEl->item(0)) ?: null;
        }

        $recipients = [];
        $recNodes = $xpath->query('//*[local-name()="GetMessageOutput"]//*[local-name()="Recipients"]/*[local-name()="string"]');
        if ($recNodes) {
            foreach ($recNodes as $n) {
                $v = trim((string)$n->textContent);
                if ($v !== '') {
                    $recipients[] = $v;
                }
            }
        }

        $confirmationName = trim((string)$xpath->evaluate('string(//*[local-name()="ConfirmationName"][1])'));

        $attachments = [];
        $attNodes = $xpath->query('//*[local-name()="GetMessageOutput"]//*[local-name()="AttachmentsOutput"]//*[local-name()="AttachmentOutput"]');
        if ($attNodes) {
            foreach ($attNodes as $attNode) {
                if (!$attNode instanceof \DOMElement) {
                    continue;
                }
                $contentId = trim((string)$xpath->evaluate('string(./*[local-name()="ContentId"][1])', $attNode));
                $isSeparateRaw = trim((string)$xpath->evaluate('string(./*[local-name()="IsSeparateCall"][1])', $attNode));
                $isSeparate = null;
                if ($isSeparateRaw === 'true') {
                    $isSeparate = true;
                } elseif ($isSeparateRaw === 'false') {
                    $isSeparate = false;
                }
                $sectionCountRaw = trim((string)$xpath->evaluate('string(./*[local-name()="SectionCount"][1])', $attNode));
                $sectionSizeRaw = trim((string)$xpath->evaluate('string(./*[local-name()="SectionSize"][1])', $attNode));
                $contentsB64 = null;
                $contentsEl = $xpath->query('./*[local-name()="Contents"][1]', $attNode)?->item(0);
                if ($contentsEl instanceof \DOMElement) {
                    $text = (string)$contentsEl->textContent;
                    $text = preg_replace('/\\s+/', '', $text) ?? $text;
                    $text = trim($text);
                    if ($text !== '') {
                        $contentsB64 = $text;
                    } else {
                        $inc = $xpath->query('.//*[local-name()="Include"][1]', $contentsEl)?->item(0);
                        if ($inc instanceof \DOMElement) {
                            $href = (string)$inc->getAttribute('href');
                            $cid = self::normalizeContentId($href);
                            if ($cid !== '' && array_key_exists($cid, $parts)) {
                                $contentsB64 = base64_encode($parts[$cid]);
                            }
                        }
                    }
                }
                $attachments[] = [
                    'ContentId' => $contentId !== '' ? $contentId : null,
                    'IsSeparateCall' => $isSeparate,
                    'SectionCount' => $sectionCountRaw !== '' ? (int)$sectionCountRaw : null,
                    'SectionSize' => $sectionSizeRaw !== '' ? (int)$sectionSizeRaw : null,
                    'Contents' => $contentsB64,
                ];
            }
        }

        return [
            'EnvelopeXml' => $envelopeXml,
            'Recipients' => $recipients,
            'ConfirmationName' => $confirmationName !== '' ? $confirmationName : null,
            'AttachmentsOutput' => !empty($attachments) ? ['AttachmentOutput' => $attachments] : null,
        ];
    }

    private static function tryParseGetAttachmentSectionResponse(string $raw): ?array
    {
        [$soapXml, $parts] = self::extractSoapXmlAndParts($raw);
        if ($soapXml === null) {
            return null;
        }
        $doc = new \DOMDocument();
        $doc->preserveWhiteSpace = false;
        $doc->formatOutput = false;
        if (!@$doc->loadXML($soapXml)) {
            return null;
        }
        $xpath = new \DOMXPath($doc);
        $contentsEl = $xpath->query('//*[local-name()="GetAttachmentSectionOutput"]//*[local-name()="Contents"][1]')?->item(0);
        $contentsB64 = null;
        if ($contentsEl instanceof \DOMElement) {
            $text = (string)$contentsEl->textContent;
            $text = preg_replace('/\\s+/', '', $text) ?? $text;
            $text = trim($text);
            if ($text !== '') {
                $contentsB64 = $text;
            } else {
                $inc = $xpath->query('.//*[local-name()="Include"][1]', $contentsEl)?->item(0);
                if ($inc instanceof \DOMElement) {
                    $href = (string)$inc->getAttribute('href');
                    $cid = self::normalizeContentId($href);
                    if ($cid !== '' && array_key_exists($cid, $parts)) {
                        $contentsB64 = base64_encode($parts[$cid]);
                    }
                }
            }
        }
        return [
            'Contents' => $contentsB64,
        ];
    }

    private static function loadSoapDom(string $raw): ?\DOMDocument
    {
        $xml = self::extractSoapXml($raw);
        if ($xml === null) {
            return null;
        }
        $doc = new \DOMDocument();
        $doc->preserveWhiteSpace = false;
        $doc->formatOutput = false;
        if (!@$doc->loadXML($xml)) {
            return null;
        }
        return $doc;
    }

    private static function extractSoapXml(string $raw): ?string
    {
        $raw = ltrim($raw);
        if ($raw === '') {
            return null;
        }
        if (str_starts_with($raw, '<')) {
            return $raw;
        }
        // DIV often responds as MTOM (multipart/related), including for SOAP Faults.
        return self::extractSoapXmlFromMultipart($raw);
    }

    /**
     * @return array{0:string|null,1:array<string,string>} SOAP XML and extra MIME parts (Content-ID => raw bytes).
     */
    private static function extractSoapXmlAndParts(string $raw): array
    {
        $raw = ltrim($raw);
        if ($raw === '') {
            return [null, []];
        }
        if (str_starts_with($raw, '<')) {
            return [$raw, []];
        }
        $parsed = self::parseMultipartRelated($raw);
        if (!$parsed) {
            return [null, []];
        }
        return [$parsed['soap_xml'] ?? null, $parsed['parts'] ?? []];
    }

    private static function extractSoapXmlFromMultipart(string $raw): ?string
    {
        $raw = ltrim($raw);
        if ($raw === '' || !str_starts_with($raw, '--')) {
            return null;
        }

        $nlPos = strpos($raw, "\n");
        $firstLine = $nlPos === false ? $raw : substr($raw, 0, $nlPos);
        $firstLine = trim($firstLine);
        if (!str_starts_with($firstLine, '--') || strlen($firstLine) < 4) {
            return null;
        }
        $boundary = substr($firstLine, 2);
        if ($boundary === '' || str_contains($boundary, ' ')) {
            // Unexpected boundary formatting; bail out rather than mis-parsing.
            return null;
        }

        $partHeaderStart = $nlPos === false ? strlen($raw) : $nlPos + 1;
        $sepLen = 0;
        $sepPos = strpos($raw, "\r\n\r\n", $partHeaderStart);
        if ($sepPos !== false) {
            $sepLen = 4;
        } else {
            $sepPos = strpos($raw, "\n\n", $partHeaderStart);
            if ($sepPos !== false) {
                $sepLen = 2;
            }
        }
        if ($sepPos === false) {
            return null;
        }
        $contentStart = $sepPos + $sepLen;

        $nextBoundaryPos = strpos($raw, "\n--" . $boundary, $contentStart);
        if ($nextBoundaryPos === false) {
            $nextBoundaryPos = strpos($raw, "\r\n--" . $boundary, $contentStart);
        }
        if ($nextBoundaryPos === false) {
            return null;
        }

        $xml = trim(substr($raw, $contentStart, $nextBoundaryPos - $contentStart));
        if ($xml === '' || !str_starts_with($xml, '<')) {
            return null;
        }
        return $xml;
    }

    /**
     * Parse a multipart/related MTOM response body.
     *
     * @return array{soap_xml:string|null, parts:array<string,string>}|null
     */
    private static function parseMultipartRelated(string $raw): ?array
    {
        $raw = ltrim($raw);
        if ($raw === '' || !str_starts_with($raw, '--')) {
            return null;
        }

        $nlPos = strpos($raw, "\n");
        $firstLine = $nlPos === false ? $raw : substr($raw, 0, $nlPos);
        $firstLine = trim($firstLine);
        if (!str_starts_with($firstLine, '--') || strlen($firstLine) < 4) {
            return null;
        }
        $boundary = substr($firstLine, 2);
        if ($boundary === '' || str_contains($boundary, ' ')) {
            return null;
        }

        $soapXml = null;
        $parts = [];

        $pos = 0;
        $boundaryMarker = '--' . $boundary;
        while (true) {
            $bPos = strpos($raw, $boundaryMarker, $pos);
            if ($bPos === false) {
                break;
            }
            $lineEnd = strpos($raw, "\n", $bPos);
            if ($lineEnd === false) {
                break;
            }
            $line = trim(substr($raw, $bPos, $lineEnd - $bPos));
            if ($line === $boundaryMarker . '--') {
                break;
            }
            $pos = $lineEnd + 1;

            $sepLen = 0;
            $sepPos = strpos($raw, "\r\n\r\n", $pos);
            if ($sepPos !== false) {
                $sepLen = 4;
            } else {
                $sepPos = strpos($raw, "\n\n", $pos);
                if ($sepPos !== false) {
                    $sepLen = 2;
                }
            }
            if ($sepPos === false) {
                break;
            }
            $headersRaw = substr($raw, $pos, $sepPos - $pos);
            $bodyStart = $sepPos + $sepLen;

            $next1 = strpos($raw, "\r\n" . $boundaryMarker, $bodyStart);
            $next2 = strpos($raw, "\n" . $boundaryMarker, $bodyStart);
            if ($next1 === false && $next2 === false) {
                break;
            }
            $next = null;
            if ($next1 !== false && $next2 !== false) {
                $next = min($next1, $next2);
            } else {
                $next = $next1 !== false ? $next1 : $next2;
            }
            if ($next === null) {
                break;
            }
            $body = substr($raw, $bodyStart, $next - $bodyStart);
            $pos = $next;

            $headers = [];
            foreach (preg_split('/\\r\\n|\\n|\\r/', (string)$headersRaw) as $hline) {
                $hline = trim((string)$hline);
                if ($hline === '') {
                    continue;
                }
                $colon = strpos($hline, ':');
                if ($colon === false) {
                    continue;
                }
                $key = strtolower(trim(substr($hline, 0, $colon)));
                $val = trim(substr($hline, $colon + 1));
                $headers[$key] = $val;
            }

            $contentType = strtolower((string)($headers['content-type'] ?? ''));
            $cte = strtolower((string)($headers['content-transfer-encoding'] ?? ''));
            $cid = self::normalizeContentId((string)($headers['content-id'] ?? ''));

            if ($cte === 'base64') {
                $bodyNorm = preg_replace('/\\s+/', '', $body) ?? $body;
                $decoded = base64_decode($bodyNorm, true);
                if ($decoded !== false) {
                    $body = $decoded;
                }
            }

            if (
                $soapXml === null
                && (
                    str_contains($contentType, 'application/xop+xml')
                    || str_contains($contentType, 'application/soap+xml')
                    || str_contains($contentType, 'text/xml')
                )
            ) {
                $soapXml = trim((string)$body);
                continue;
            }
            if ($cid !== '') {
                $parts[$cid] = (string)$body;
            }
        }

        if ($soapXml === null) {
            // Fallback: attempt to extract the first part as SOAP XML (legacy behavior).
            $soapXml = self::extractSoapXmlFromMultipart($raw);
        }
        if ($soapXml === null) {
            return null;
        }
        return [
            'soap_xml' => $soapXml,
            'parts' => $parts,
        ];
    }

    private static function normalizeContentId(string $value): string
    {
        $value = trim($value);
        if ($value === '') {
            return '';
        }
        if (str_starts_with(strtolower($value), 'cid:')) {
            $value = substr($value, 4);
        }
        $value = trim($value);
        if (str_starts_with($value, '<') && str_ends_with($value, '>')) {
            $value = substr($value, 1, -1);
        }
        return trim($value);
    }
}
