<?php
// eadrese_client.php
// -----------------------------------------------------------------------------
//  This file provides a minimal, framework‑agnostic client for Latvia’s e‑adrese
//  (VRAA VUS) service in pure PHP.  It follows the same high‑level structure
//  as the reference Python implementation: obtain an OAuth2 access token via
//  the client‑credentials flow, build a message envelope, and invoke the
//  UnifiedService SOAP endpoint to send a message.  The exact SOAP element
//  names may need to be adjusted to match the WSDL once obtained.

/**
 * Configuration for the e‑adrese client: OAuth2 credentials, certificate
 * material and service endpoints.  Defaults point to the DIV sandbox.
 */
class EAddressConfig
{
    public string $clientId;
    public string $clientSecret;
    public ?string $certificate;
    public ?string $privateKey;
    public string $wsdlUrl;
    public string $tokenUrl;
    public bool $verifySsl;

    /**
     * @param string      $clientId     OAuth2 client ID issued by VDAA.
     * @param string      $clientSecret OAuth2 client secret.
     * @param string|null $certificate  Optional path to QWAC certificate (PEM).
     * @param string|null $privateKey   Optional path to matching private key (PEM).
     * @param string      $wsdlUrl      UnifiedService WSDL URL (sandbox by default).
     * @param string      $tokenUrl     OAuth2 token endpoint (sandbox by default).
     * @param bool        $verifySsl    Whether to verify server certificates.
     */
    public function __construct(
        string $clientId,
        string $clientSecret,
        ?string $certificate = null,
        ?string $privateKey = null,
        string $wsdlUrl = 'https://div.vraa.gov.lv/UnifiedService.svc?wsdl',
        string $tokenUrl = 'https://div.vraa.gov.lv/Auth/token',
        bool $verifySsl = true
    ) {
        $this->clientId    = $clientId;
        $this->clientSecret = $clientSecret;
        $this->certificate  = $certificate;
        $this->privateKey   = $privateKey;
        $this->wsdlUrl      = $wsdlUrl;
        $this->tokenUrl     = $tokenUrl;
        $this->verifySsl    = $verifySsl;
    }
}

/**
 * Represents an attachment to be sent with a message.  Content is base64
 * encoded when created from file, as SOAP attachments expect binary data
 * encoded as strings.
 */
class Attachment
{
    public string $filename;
    public string $content;
    public string $contentType;

    public function __construct(string $filename, string $content, string $contentType = 'application/octet-stream')
    {
        $this->filename    = $filename;
        $this->content     = $content;
        $this->contentType = $contentType;
    }

    /**
     * Build an Attachment from a local file.  The file content is read
     * into memory and base64 encoded.  If no content type is provided the
     * extension is passed through PHP’s mime_content_type().
     *
     * @param string      $path         Path to the file on disk.
     * @param string|null $contentType  Optional MIME type override.
     * @return Attachment
     */
    public static function fromFile(string $path, ?string $contentType = null): self
    {
        if (!is_readable($path)) {
            throw new InvalidArgumentException("Attachment file not readable: {$path}");
        }
        $data = file_get_contents($path);
        $ctype = $contentType ?? mime_content_type($path) ?? 'application/octet-stream';
        return new self(basename($path), base64_encode($data), $ctype);
    }
}

/**
 * Exception type for any VUS or transport‑level errors.  Carries the raw
 * response (if available) for diagnostic purposes.
 */
class EAddressError extends RuntimeException
{
    public ?array $response;

    public function __construct(string $message, ?array $response = null)
    {
        parent::__construct($message);
        $this->response = $response;
    }
}

/**
 * A minimal client for the VRAA e‑adrese UnifiedService.
 *
 * This class hides the mechanics of retrieving an OAuth2 access token
 * (client‑credentials grant), building an envelope and calling the SOAP
 * method.  It is deliberately kept simple and may need refinement once
 * you obtain the WSDL and verify parameter names.
 */
class EAddressClient
{
    private EAddressConfig $cfg;
    private ?string $token = null;
    private ?int $tokenExpiry = null;
    private SoapClient $soap;

    public function __construct(EAddressConfig $cfg)
    {
        $this->cfg = $cfg;
        $contextOptions = [];
        // Configure SSL verification and client certificates.
        if (!$cfg->verifySsl) {
            $contextOptions['ssl'] = [
                'verify_peer'      => false,
                'verify_peer_name' => false,
            ];
        }
        if ($cfg->certificate && $cfg->privateKey) {
            $contextOptions['ssl'] = ($contextOptions['ssl'] ?? []) + [
                'local_cert' => $cfg->certificate,
                'local_pk'   => $cfg->privateKey,
            ];
        }
        $streamContext = stream_context_create($contextOptions);

        // Instantiate the SoapClient with the provided WSDL.
        $this->soap = new SoapClient($cfg->wsdlUrl, [
            'trace'         => true,
            'exceptions'    => true,
            'stream_context'=> $streamContext,
            'connection_timeout' => 30,
        ]);
    }

    /**
     * Retrieve (or refresh) an OAuth2 access token using the client credentials
     * grant.  The token is cached until shortly before expiry.
     *
     * @return string The bearer token.
     * @throws EAddressError on failure to obtain a token.
     */
    private function getToken(): string
    {
        // Reuse token if still valid (with a one minute margin).
        if ($this->token && $this->tokenExpiry && time() < $this->tokenExpiry - 60) {
            return $this->token;
        }
        $ch = curl_init($this->cfg->tokenUrl);
        $postData = http_build_query(['grant_type' => 'client_credentials']);
        $headers = [
            'Content-Type: application/x-www-form-urlencoded',
            'Accept: application/json',
        ];
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $postData,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_USERPWD        => $this->cfg->clientId . ':' . $this->cfg->clientSecret,
        ]);
        if (!$this->cfg->verifySsl) {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        }
        $raw = curl_exec($ch);
        if ($raw === false) {
            $error = curl_error($ch);
            curl_close($ch);
            throw new EAddressError("Failed to obtain OAuth2 token: {$error}");
        }
        curl_close($ch);
        $response = json_decode($raw, true);
        if (!isset($response['access_token'])) {
            throw new EAddressError('OAuth2 token response did not contain access_token', $response);
        }
        $this->token       = $response['access_token'];
        $expiresIn         = $response['expires_in'] ?? 3600;
        $this->tokenExpiry = time() + (int)$expiresIn;
        return $this->token;
    }

    /**
     * Build the message envelope expected by the UnifiedService.  This
     * implementation constructs a simple associative array; adjust keys
     * according to the actual WSDL definitions (for example, wrapping under
     * Message/Recipient/PersonCode, etc.).
     *
     * @param string       $recipientPersonalCode Personal code of the recipient.
     * @param string       $documentKindCode      Document kind (e.g. "EINVOICE").
     * @param string       $subject               Message subject.
     * @param string       $bodyText              Message body.
     * @param Attachment[] $attachments           Array of Attachment objects.
     * @return array
     */
    private function buildEnvelope(
        string $recipientPersonalCode,
        string $documentKindCode,
        string $subject,
        string $bodyText,
        array $attachments
    ): array {
        $envelope = [
            // The exact key structure depends on the WSDL.  The Python version
            // builds a dictionary with keys recipientPersonCode, documentKindCode,
            // subject, bodyText and attachments.  Use the WSDL to refine.
            'recipientPersonalCode' => $recipientPersonalCode,
            'documentKindCode'      => $documentKindCode,
            'subject'               => $subject,
            'bodyText'              => $bodyText,
            'attachments'           => [],
        ];
        foreach ($attachments as $att) {
            $envelope['attachments'][] = [
                'filename'    => $att->filename,
                'contentType' => $att->contentType,
                'content'     => $att->content,
            ];
        }
        return $envelope;
    }

    /**
     * Send a single e‑adrese message and return the assigned messageId.  In
     * case of an error a descriptive exception is thrown.
     *
     * @param string       $recipientPersonalCode Recipient person code (Latvian ID).
     * @param string       $documentKindCode      Kind code (default "EINVOICE").
     * @param string       $subject               Message subject.
     * @param string       $bodyText              Message body text.
     * @param Attachment[] $attachments           Attachments to include.
     * @return string                            Message ID on success.
     * @throws EAddressError                      On SOAP or transport error.
     */
    public function sendMessage(
        string $recipientPersonalCode,
        string $documentKindCode = 'EINVOICE',
        string $subject = 'Elektroniskais rēķins',
        string $bodyText = 'Lūdzu, skatiet pielikumā e‑rēķinu.',
        array $attachments = []
    ): string {
        $token   = $this->getToken();
        $envelope = $this->buildEnvelope(
            $recipientPersonalCode,
            $documentKindCode,
            $subject,
            $bodyText,
            $attachments
        );

        // Build SOAP header with the bearer token.  The namespace used here
        // (http://vraa.gov.lv) is illustrative; consult the WSDL for the
        // correct namespace URI and header name.
        $authHeader = new SoapHeader(
            'http://vraa.gov.lv',
            'Authorization',
            'Bearer ' . $token
        );
        // Prepare the parameters.  The parameter name (e.g. 'message') must
        // correspond to the WSDL operation signature.  Adjust accordingly.
        $params = [
            'message' => $envelope,
        ];
        try {
            $response = $this->soap->__soapCall('SendMessage', [$params], null, $authHeader);
            // Attempt to extract messageId; adjust property name based on WSDL.
            if (is_object($response) && isset($response->messageId)) {
                return (string)$response->messageId;
            }
            // If the structure differs, return the raw response as JSON string
            return json_encode($response);
        } catch (SoapFault $fault) {
            // Convert SOAP faults into our custom exception for consistency.
            throw new EAddressError('SOAP fault: ' . $fault->getMessage());
        }
    }
}
