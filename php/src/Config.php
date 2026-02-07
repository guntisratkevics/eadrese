<?php

declare(strict_types=1);

namespace LatvianEinvoice;

final class Config
{
    public string $wsdlUrl;
    public string $tokenUrl;
    public string $clientId;
    public string $clientSecret;

    public ?string $clientCertPath;
    public ?string $clientKeyPath;
    public ?string $certificatePath;
    public ?string $privateKeyPath;

    public bool $verifySsl;
    public string $defaultFrom;
    public string $defaultTo;

    public bool $vidSubaddressAuto;
    public ?string $vidSubaddress;
    public string $encryptionMode;

    public function __construct(
        string $wsdlUrl,
        string $tokenUrl = '',
        string $clientId = '',
        string $clientSecret = '',
        ?string $clientCertPath = null,
        ?string $clientKeyPath = null,
        ?string $certificatePath = null,
        ?string $privateKeyPath = null,
        bool $verifySsl = true,
        string $defaultFrom = '_DEFAULT@90000000000',
        string $defaultTo = '_PRIVATE@10000000000',
        bool $vidSubaddressAuto = false,
        ?string $vidSubaddress = null,
        string $encryptionMode = 'gcm'
    ) {
        $this->wsdlUrl = $wsdlUrl;
        $this->tokenUrl = $tokenUrl;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->clientCertPath = $clientCertPath;
        $this->clientKeyPath = $clientKeyPath;
        $this->certificatePath = $certificatePath;
        $this->privateKeyPath = $privateKeyPath;
        $this->verifySsl = $verifySsl;
        $this->defaultFrom = $defaultFrom;
        $this->defaultTo = $defaultTo;
        $this->vidSubaddressAuto = $vidSubaddressAuto;
        $this->vidSubaddress = $vidSubaddress;
        $this->encryptionMode = $encryptionMode;
    }
}
