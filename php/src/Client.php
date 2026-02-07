<?php

declare(strict_types=1);

namespace LatvianEinvoice;

use LatvianEinvoice\Envelope\Builder;

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

    public function sendMessage(): void
    {
        throw new \RuntimeException('SendMessage is not implemented in the PHP client yet.');
    }
}
