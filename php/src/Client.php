<?php

declare(strict_types=1);

namespace LatvianEinvoice;

use LatvianEinvoice\Envelope\Builder;
use LatvianEinvoice\Soap\DirectSoapClient;
use LatvianEinvoice\Soap\DivMessageDecoder;

final class Client
{
    private Config $config;

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    /**
     * @param string[] $recipients
     * @param Attachment[] $attachments
     * @return array{0: array, 1: array|null, 2: string}
     */
    public function buildEnvelope(
        array $recipients,
        string $documentKindCode = 'EINVOICE',
        string $subject = 'Electronic invoice',
        string $bodyText = 'Please see the attached e-invoice.',
        array $attachments = [],
        ?string $encryptionKeyB64 = null,
        ?string $recipientThumbprintB64 = null,
        ?string $symmetricKeyBytes = null,
        ?string $symmetricIvBytes = null,
        ?string $traceText = 'Created',
        bool $notifySenderOnDelivery = false,
        ?string $encryptionMode = null
    ): array {
        return Builder::buildEnvelope(
            $this->config->defaultFrom,
            $recipients,
            $documentKindCode,
            $subject,
            $bodyText,
            $attachments,
            $encryptionKeyB64,
            $recipientThumbprintB64,
            $symmetricKeyBytes,
            $symmetricIvBytes,
            $encryptionMode ?? $this->config->encryptionMode,
            $traceText,
            $notifySenderOnDelivery
        );
    }

    public function createSoapClient(): \SoapClient
    {
        $options = [
            'trace' => 1,
            'exceptions' => true,
            'cache_wsdl' => WSDL_CACHE_NONE,
        ];
        if ($this->config->clientCertPath) {
            $options['local_cert'] = $this->config->clientCertPath;
        }
        if ($this->config->clientKeyPath) {
            $options['local_pk'] = $this->config->clientKeyPath;
        }
        if (!$this->config->verifySsl) {
            $options['stream_context'] = stream_context_create([
                'ssl' => [
                    'verify_peer' => false,
                    'verify_peer_name' => false,
                ],
            ]);
        }
        return new \SoapClient($this->config->wsdlUrl, $options);
    }

    /**
     * Direct SOAP SendMessage (mTLS + WSSE + SenderDocument signature).
     *
     * @param string[] $recipients
     * @return array{status:int, body:array|null, raw:string, request_xml:string, message_id:string}
     */
    public function sendTextMessageSoap(
        array $recipients,
        string $subject,
        string $bodyText = '',
        string $documentKindCode = 'DOC_EMPTY'
    ): array {
        $soap = new DirectSoapClient($this->config);
        return $soap->sendTextMessage(
            $recipients,
            $subject,
            $bodyText,
            $documentKindCode
        );
    }

    /**
     * Direct SOAP GetMessageList.
     *
     * @return array{status:int, body:array|null, raw:string, request_xml:string}
     */
    public function getMessageListSoap(int $maxResultCount = 10, ?int $addresseeUnitId = null): array
    {
        $soap = new DirectSoapClient($this->config);
        return $soap->getMessageList($maxResultCount, $addresseeUnitId);
    }

    /**
     * Direct SOAP GetMessage.
     *
     * @return array{status:int, body:array|null, raw:string, request_xml:string}
     */
    public function getMessageSoap(string $messageId): array
    {
        $soap = new DirectSoapClient($this->config);
        return $soap->getMessage($messageId);
    }

    /**
     * Direct SOAP ConfirmMessage.
     *
     * @param string[]|null $recipientEaddresses
     * @return array{status:int, body:array|null, raw:string, request_xml:string}
     */
    public function confirmMessageSoap(
        string $messageId,
        string $status = 'RecipientAccepted',
        ?string $statusCode = null,
        ?string $statusReason = null,
        ?array $recipientEaddresses = null
    ): array {
        $soap = new DirectSoapClient($this->config);
        return $soap->confirmMessage($messageId, $status, $statusCode, $statusReason, $recipientEaddresses);
    }

    /**
     * Direct SOAP GetMessage + optional attachment section stitching + decrypt/decompress.
     *
     * @return array{status:int, body:array|null, raw:string, request_xml:string}
     */
    public function getMessageDecodedSoap(
        string $messageId,
        bool $stitchSections = true,
        bool $decrypt = true
    ): array {
        $soap = new DirectSoapClient($this->config);
        $result = $soap->getMessage($messageId);
        $body = is_array($result['body'] ?? null) ? $result['body'] : null;
        if (!$body || isset($body['Fault'])) {
            return $result;
        }
        if ($stitchSections) {
            DivMessageDecoder::stitchAttachmentSections($soap, $messageId, $body);
        }
        if ($decrypt) {
            DivMessageDecoder::decryptAttachments($body, $this->config);
        }
        $result['body'] = $body;
        return $result;
    }

    public function sendMessage(): void
    {
        throw new \RuntimeException('SendMessage is not implemented in the PHP client yet.');
    }
}
