<?php

declare(strict_types=1);

namespace LatvianEinvoice;

use LatvianEinvoice\Envelope\Builder;
use LatvianEinvoice\Soap\DirectSoapClient;
use LatvianEinvoice\Soap\DivMessageDecoder;
use LatvianEinvoice\Soap\DivMessageSummary;
use LatvianEinvoice\Utils\Crypto;

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
        ?string $encryptionMode = null,
        ?array $recipientEntries = null
    ): array {
        $normalizedRecipients = $this->normalizeRecipientsForSend($recipients, $documentKindCode);

        return Builder::buildEnvelope(
            $this->config->defaultFrom,
            $normalizedRecipients,
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
            $notifySenderOnDelivery,
            $recipientEntries
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
        $normalizedRecipients = $this->normalizeRecipientsForSend($recipients, $documentKindCode);
        $soap = new DirectSoapClient($this->config);
        return $soap->sendTextMessage(
            $normalizedRecipients,
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

    /**
     * Direct SOAP GetMessage + structured message/file info extracted from EnvelopeXml.
     *
     * Convenience helper for callers who want ready-to-use document, sender,
     * recipient, and attachment metadata without manually parsing the DIV envelope.
     *
     * @return array<string,mixed>|null
     */
    public function getMessageAndFileInfoSoap(
        string $messageId,
        bool $stitchSections = true,
        bool $decrypt = true
    ): ?array {
        $result = $this->getMessageDecodedSoap($messageId, $stitchSections, $decrypt);
        $body = is_array($result['body'] ?? null) ? $result['body'] : null;
        if (!$body || array_key_exists('Fault', $body)) {
            return null;
        }
        return DivMessageSummary::build($body);
    }

    /**
     * Direct SOAP GetMessageList + first message fetch convenience (PHP equivalent of Python get_next_message()).
     *
     * @return array{status:int, body:array|null, raw:string, request_xml:string, confirmed?:bool, confirm_error?:string}|null
     */
    public function getNextMessageSoap(
        bool $includeAttachments = true,
        bool $stitchSections = true,
        bool $decrypt = true,
        bool $autoConfirm = false
    ): ?array {
        $list = $this->getMessageListSoap(10);
        $listBody = is_array($list['body'] ?? null) ? $list['body'] : null;
        $headers = is_array($listBody['MessageHeaders'] ?? null) ? $listBody['MessageHeaders'] : [];
        $first = (isset($headers[0]) && is_array($headers[0])) ? $headers[0] : null;
        $messageId = trim((string)($first['MessageId'] ?? ''));
        if ($messageId === '') {
            return null;
        }

        $result = $this->getMessageDecodedSoap(
            $messageId,
            $includeAttachments && $stitchSections,
            $includeAttachments && $decrypt
        );

        if ($autoConfirm) {
            $confirm = $this->confirmMessageSoap($messageId);
            $confirmBody = is_array($confirm['body'] ?? null) ? $confirm['body'] : null;
            $hasFault = is_array($confirmBody) && array_key_exists('Fault', $confirmBody);
            $result['confirmed'] = !$hasFault;
            if ($hasFault) {
                $result['confirm_error'] = self::faultText($confirmBody);
            }
        }
        return $result;
    }

    /**
     * Direct SOAP SearchAddresseeUnit.
     *
     * @return array{status:int, body:array|null, raw:string, request_xml:string, results:list<array<string,mixed>>}
     */
    public function searchAddresseeSoap(string $registrationNumber): array
    {
        $soap = new DirectSoapClient($this->config);
        return $soap->searchAddresseeUnit($registrationNumber);
    }

    /**
     * Direct SOAP GetPublicKeyList.
     *
     * @param string[] $recipients
     * @return array{status:int, body:array|null, raw:string, request_xml:string, keys:list<array<string,mixed>>}
     */
    public function getPublicKeyListSoap(array $recipients): array
    {
        $soap = new DirectSoapClient($this->config);
        return $soap->getPublicKeyList($recipients);
    }

    /**
     * Direct SOAP GetNotificationList.
     *
     * @return array{status:int, body:array|null, raw:string, request_xml:string}
     */
    public function getNotificationListSoap(int $maxResultCount = 50): array
    {
        $soap = new DirectSoapClient($this->config);
        return $soap->getNotificationList($maxResultCount);
    }

    /**
     * Direct SOAP ConfirmNotificationList.
     *
     * @param int[] $notificationIds
     * @return array{status:int, body:array|null, raw:string, request_xml:string, confirmed_ids:list<int>}
     */
    public function confirmNotificationListSoap(array $notificationIds): array
    {
        $soap = new DirectSoapClient($this->config);
        return $soap->confirmNotificationList($notificationIds);
    }

    /**
     * Poll notifications with paging + optional auto-confirm behavior.
     *
     * @return array{items:list<array<string,mixed>>,has_more_data:bool,confirmed_ids:list<int>}
     */
    public function pollNotificationsSoap(int $maxItems = 50, bool $autoConfirm = true): array
    {
        $limit = max(min($maxItems, 200), 1);
        $items = [];
        $confirmedIds = [];
        $hasMoreData = false;
        $seenNotificationIds = [];
        $remaining = $limit;

        while ($remaining > 0) {
            $response = $this->getNotificationListSoap($remaining);
            $body = is_array($response['body'] ?? null) ? $response['body'] : [];
            if (array_key_exists('Fault', $body)) {
                throw new \RuntimeException('GetNotificationList failed: ' . self::faultText($body));
            }

            $batch = self::extractNotificationItems($body);
            $hasMoreData = (bool)($body['HasMoreData'] ?? false);
            if (empty($batch)) {
                break;
            }

            $batchIds = [];
            $filteredBatch = [];
            foreach ($batch as $notification) {
                $notificationId = self::toInt($notification['id'] ?? null);
                if ($notificationId !== null) {
                    if (isset($seenNotificationIds[$notificationId])) {
                        continue;
                    }
                    $seenNotificationIds[$notificationId] = true;
                    $batchIds[] = $notificationId;
                }
                $filteredBatch[] = $notification;
            }

            if (empty($filteredBatch)) {
                break;
            }

            $items = array_merge($items, $filteredBatch);
            $remaining = $limit - count($items);

            if ($autoConfirm && !empty($batchIds)) {
                $confirm = $this->confirmNotificationListSoap($batchIds);
                $confirmBody = is_array($confirm['body'] ?? null) ? $confirm['body'] : [];
                if (array_key_exists('Fault', $confirmBody)) {
                    break;
                }
                foreach (($confirm['confirmed_ids'] ?? []) as $confirmedId) {
                    $id = self::toInt($confirmedId);
                    if ($id !== null) {
                        $confirmedIds[$id] = $id;
                    }
                }
            }

            if (!$hasMoreData || $remaining <= 0) {
                break;
            }
        }

        return [
            'items' => array_slice($items, 0, $limit),
            'has_more_data' => $hasMoreData,
            'confirmed_ids' => array_values($confirmedIds),
        ];
    }

    /**
     * Certificate/connectivity validation helper for smoke checks and setup verification.
     *
     * @param string[] $lookupValues
     * @return array{status:string,message:string,lookup_value?:string,attempted_values:array<int,string>,errors?:array<int,string>}
     */
    public function certValidateSoap(array $lookupValues): array
    {
        $attemptedValues = [];
        $errors = [];

        foreach ($lookupValues as $rawValue) {
            $value = trim((string)$rawValue);
            if ($value === '' || in_array($value, $attemptedValues, true)) {
                continue;
            }
            $attemptedValues[] = $value;
            try {
                $response = $this->searchAddresseeSoap($value);
                $body = is_array($response['body'] ?? null) ? $response['body'] : [];
                if (array_key_exists('Fault', $body)) {
                    $errors[] = $value . ': ' . self::faultText($body);
                    continue;
                }
                $results = is_array($response['results'] ?? null) ? $response['results'] : [];
                if (!empty($results)) {
                    return [
                        'status' => 'ok',
                        'message' => 'Certificate valid and connectivity working.',
                        'lookup_value' => $value,
                        'attempted_values' => $attemptedValues,
                    ];
                }
                $errors[] = $value . ': no results';
            } catch (\Throwable $exc) {
                $errors[] = $value . ': ' . (trim($exc->getMessage()) !== '' ? $exc->getMessage() : $exc::class);
            }
        }

        $message = !empty($errors) ? $errors[0] : 'Certificate validation lookup failed.';
        return [
            'status' => 'error',
            'message' => $message,
            'attempted_values' => $attemptedValues,
            'errors' => $errors,
        ];
    }

    /**
     * Direct SOAP SendMessage using Envelope\Builder output.
     *
     * @param string[] $recipients
     * @param Attachment[] $attachments
     * @return array{status:int, body:array|null, raw:string, request_xml:string, message_id:string}
     */
    public function sendMessage(
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
        ?string $encryptionMode = null,
        ?string $recipientCertPath = null,
        ?string $recipientCertPem = null,
        ?string $recipientPublicKeyModulusB64 = null,
        ?string $recipientPublicKeyExponentB64 = null
    ): array {
        $mode = strtolower(trim((string)($encryptionMode ?? $this->config->encryptionMode ?: 'gcm')));
        $encryptionKey = $encryptionKeyB64;
        $thumbprint = $recipientThumbprintB64;
        $symmetricKey = $symmetricKeyBytes;
        $symmetricIv = $symmetricIvBytes;

        $modulusB64 = trim((string)($recipientPublicKeyModulusB64 ?? ''));
        $exponentB64 = trim((string)($recipientPublicKeyExponentB64 ?? ''));
        $perRecipientEntries = null;

        if ($modulusB64 !== '' && $exponentB64 !== '') {
            if (trim((string)$thumbprint) === '') {
                throw new \RuntimeException(
                    'recipientThumbprintB64 is required when recipientPublicKeyModulusB64/ExponentB64 are provided'
                );
            }
            if (!in_array($mode, ['oaep_cbc', 'cbc'], true)) {
                throw new \RuntimeException('recipient public key modulus/exponent flow requires oaep_cbc mode');
            }
            $symmetricKey = $symmetricKey ?? random_bytes(32);
            $symmetricIv = $symmetricIv ?? random_bytes(16);
            $keyBlob = Crypto::buildDivKeyBlob($symmetricKey, $symmetricIv);
            $encryptionKey = Crypto::encryptKeyOaepSha1FromModExp($modulusB64, $exponentB64, $keyBlob);
        } elseif ($recipientCertPath !== null || $recipientCertPem !== null) {
            $certPem = self::resolveRecipientCertPem($recipientCertPath, $recipientCertPem);
            if ($certPem !== null) {
                if (in_array($mode, ['oaep_cbc', 'cbc'], true)) {
                    [$encryptionKey, $thumbprint, $symmetricKey, $symmetricIv] =
                        Crypto::deriveEncryptionFieldsOaepCbc($certPem, $symmetricKey, $symmetricIv);
                } else {
                    [$encryptionKey, $thumbprint, $symmetricKey] =
                        Crypto::deriveEncryptionFields($certPem, $symmetricKey);
                }
            }
        } elseif ($documentKindCode === 'EINVOICE' && $encryptionKey === null) {
            $normalizedForFetch = $this->normalizeRecipientsForSend($recipients, $documentKindCode);
            $soap = new DirectSoapClient($this->config);
            $pkResult = $soap->getPublicKeyList($normalizedForFetch);
            $publicKeyMap = self::buildPublicKeyMap($pkResult['keys'] ?? []);
            if (!empty($publicKeyMap)) {
                if (!in_array($mode, ['oaep_cbc', 'cbc'], true)) {
                    $mode = 'oaep_cbc';
                }
                $symmetricKey = $symmetricKey ?? random_bytes(32);
                $symmetricIv = $symmetricIv ?? random_bytes(16);
                $keyBlob = Crypto::buildDivKeyBlob($symmetricKey, $symmetricIv);
                $perRecipientEntries = [];
                foreach ($normalizedForFetch as $addr) {
                    $entry = ['RecipientE-Address' => $addr];
                    $pkInfo = $publicKeyMap[strtolower($addr)] ?? null;
                    if ($pkInfo !== null) {
                        $encKeyForRecipient = Crypto::encryptKeyOaepSha1FromModExp(
                            $pkInfo['modulus'],
                            $pkInfo['exponent'],
                            $keyBlob
                        );
                        $entry['EncryptionInfo'] = [
                            'Key' => $encKeyForRecipient,
                            'CertificateThumbprint' => $pkInfo['thumbprint'],
                        ];
                    }
                    $perRecipientEntries[] = $entry;
                }
            }
        }

        [$envelope, $attachmentsInput, $messageId] = $this->buildEnvelope(
            $recipients,
            $documentKindCode,
            $subject,
            $bodyText,
            $attachments,
            $encryptionKey,
            $thumbprint,
            $symmetricKey,
            $symmetricIv,
            $traceText,
            $notifySenderOnDelivery,
            $mode,
            $perRecipientEntries
        );

        $soap = new DirectSoapClient($this->config);
        return $soap->sendMessageFromEnvelope(
            $envelope,
            is_array($attachmentsInput) ? $attachmentsInput : null,
            $messageId
        );
    }

    /**
     * @param array<string,mixed> $body
     * @return array<int,array<string,mixed>>
     */
    private static function extractNotificationItems(array $body): array
    {
        $notifications = $body['Notifications'] ?? null;
        if (is_array($notifications)) {
            $notifications = $notifications['Notification'] ?? $notifications;
        }
        if (!is_array($notifications)) {
            return [];
        }
        if (isset($notifications['Id']) || isset($notifications['MessageId'])) {
            $notifications = [$notifications];
        }

        $items = [];
        foreach ($notifications as $row) {
            if (!is_array($row)) {
                continue;
            }
            $recipients = self::normalizeRecipientStrings($row['Recipients'] ?? null);
            $items[] = [
                'id' => $row['Id'] ?? null,
                'type' => $row['Type'] ?? null,
                'created_on' => $row['CreatedOn'] ?? null,
                'message_id' => $row['MessageId'] ?? null,
                'message_client_id' => $row['MessageClientId'] ?? null,
                'message_status' => $row['MessageStatus'] ?? null,
                'status_code' => $row['StatusCode'] ?? null,
                'status_text' => $row['StatusText'] ?? null,
                'sender' => $row['Sender'] ?? null,
                'recipients' => $recipients,
            ];
        }
        return $items;
    }

    /**
     * @return string[]
     */
    private static function normalizeRecipientStrings(mixed $value): array
    {
        if (!is_array($value)) {
            return [];
        }
        $rawRecipients = $value['string'] ?? $value;
        if (is_string($rawRecipients)) {
            $rawRecipients = [$rawRecipients];
        }
        if (!is_array($rawRecipients)) {
            return [];
        }

        $recipients = [];
        foreach ($rawRecipients as $recipient) {
            if (!is_string($recipient) && !is_int($recipient) && !is_float($recipient)) {
                continue;
            }
            $text = trim((string)$recipient);
            if ($text !== '') {
                $recipients[] = $text;
            }
        }
        return $recipients;
    }

    private static function toInt(mixed $value): ?int
    {
        if (!is_string($value) && !is_int($value) && !is_float($value)) {
            return null;
        }
        $text = trim((string)$value);
        if ($text === '' || !preg_match('/^-?\d+$/', $text)) {
            return null;
        }
        return (int)$text;
    }

    /**
     * @param array<string,mixed>|null $body
     */
    private static function faultText(?array $body): string
    {
        if (!is_array($body)) {
            return 'Unknown SOAP fault';
        }
        $fault = is_array($body['Fault'] ?? null) ? $body['Fault'] : [];
        $parts = [];
        foreach (['Code', 'Reason', 'Detail'] as $key) {
            $value = trim((string)($fault[$key] ?? ''));
            if ($value !== '') {
                $parts[] = $value;
            }
        }
        return !empty($parts) ? implode(' | ', $parts) : 'Unknown SOAP fault';
    }

    /**
     * @param string[] $recipients
     * @return string[]
     */
    private function normalizeRecipientsForSend(array $recipients, string $documentKindCode): array
    {
        $normalized = [];
        foreach ($recipients as $recipient) {
            $value = trim((string)$recipient);
            if ($value !== '' && !in_array($value, $normalized, true)) {
                $normalized[] = $value;
            }
        }

        if (empty($normalized)) {
            $fallback = trim((string)$this->config->defaultTo);
            if ($fallback !== '') {
                $normalized[] = $fallback;
            }
        }

        if (
            $this->config->vidSubaddressAuto
            && strtoupper(trim($documentKindCode)) === 'EINVOICE'
        ) {
            $vid = trim((string)($this->config->vidSubaddress ?? ''));
            if ($vid === '') {
                $vid = $this->deriveDefaultVidSubaddress();
            }
            if ($vid !== '' && !in_array($vid, $normalized, true)) {
                $normalized[] = $vid;
            }
        }

        return $normalized;
    }

    private function deriveDefaultVidSubaddress(): string
    {
        $wsdl = strtolower(trim((string)$this->config->wsdlUrl));
        $token = strtolower(trim((string)$this->config->tokenUrl));
        $isTest = str_contains($wsdl, 'divtest') || str_contains($token, 'divtest');
        return $isTest ? 'VID_EREKINI_TEST@90000069281' : 'VID_EREKINI_PROD@90000069281';
    }

    /**
     * Build a lowercase-keyed map of public key info from getPublicKeyList() result.
     *
     * @param array<int,array<string,mixed>> $keys  Raw key entries from DirectSoapClient::getPublicKeyList()
     * @return array<string,array{modulus:string,exponent:string,thumbprint:string}>
     */
    private static function buildPublicKeyMap(array $keys): array
    {
        $map = [];
        foreach ($keys as $key) {
            $addr      = trim((string)($key['EAddress']               ?? $key['eaddress']               ?? ''));
            $modulus   = trim((string)($key['Modulus']                ?? $key['modulus']                ?? ''));
            $exponent  = trim((string)($key['Exponent']               ?? $key['exponent']               ?? ''));
            $thumbprint = trim((string)($key['CertificateThumbprint'] ?? $key['certificateThumbprint']  ?? ''));
            if ($addr === '' || $modulus === '' || $exponent === '' || $thumbprint === '') {
                continue;
            }
            $map[strtolower($addr)] = [
                'modulus'    => $modulus,
                'exponent'   => $exponent,
                'thumbprint' => $thumbprint,
            ];
        }
        return $map;
    }

    /**
     * Direct SOAP GetInitialAddresseeRecordList — full initial sync of VRAA addressee directory.
     *
     * Automatically paginates using ContinuationToken and returns all records in one call.
     * Pass $allPages = false with an explicit $continuationToken to fetch a single page.
     *
     * @return array{status:int, body:array|null, raw:string, request_xml:string, records:list<array<string,mixed>>, continuation_token:string|null}
     */
    public function getInitialAddresseeRecordListSoap(?string $continuationToken = null, bool $allPages = true): array
    {
        $soap = new DirectSoapClient($this->config);
        return $soap->getInitialAddresseeRecordList($continuationToken, $allPages);
    }

    /**
     * Direct SOAP GetChangedAddresseeRecordList — incremental sync of VRAA addressee directory.
     *
     * Returns all records changed since the given version number.
     * Use the highest Version value from a previous sync as $lastVersion.
     *
     * @return array{status:int, body:array|null, raw:string, request_xml:string, records:list<array<string,mixed>>, has_more_data:bool}
     */
    public function getChangedAddresseeRecordListSoap(int $lastVersion = 0): array
    {
        $soap = new DirectSoapClient($this->config);
        return $soap->getChangedAddresseeRecordList($lastVersion);
    }

    /**
     * Direct SOAP ValidateEAddress — validate e-addresses in the VRAA directory.
     *
     * @param string[] $eAddresses
     * @param string|null $type 'NaturalPerson', 'RegisteredEntity', or null (no filter)
     * @return array{status:int, body:array|null, raw:string, request_xml:string, results:list<array<string,mixed>>}
     */
    public function validateEAddressSoap(array $eAddresses, ?string $type = null): array
    {
        $soap = new DirectSoapClient($this->config);
        return $soap->validateEAddress($eAddresses, $type);
    }

    /**
     * Direct SOAP GetAddresseeUnit — fetch full unit metadata for an addressee.
     *
     * ⚠️  Restricted to government institutions managing their own DIV units.
     * Commercial clients will receive a permission error. Use searchAddresseeSoap() instead.
     *
     * @return array{status:int, body:array|null, raw:string, request_xml:string, unit:array<string,mixed>|null}
     */
    public function getAddresseeUnitSoap(string $query): array
    {
        $soap = new DirectSoapClient($this->config);
        return $soap->getAddresseeUnit($query);
    }

    /**
     * Direct SOAP GetMessageServerConfirmation — get server confirmation for a sent message.
     *
     * @return array{status:int, body:array|null, raw:string, request_xml:string}
     */
    public function getMessageServerConfirmationSoap(string $messageId): array
    {
        $soap = new DirectSoapClient($this->config);
        return $soap->getMessageServerConfirmation($messageId);
    }

    private static function resolveRecipientCertPem(?string $recipientCertPath, ?string $recipientCertPem): ?string
    {
        $inlinePem = trim((string)($recipientCertPem ?? ''));
        if ($inlinePem !== '') {
            return $inlinePem;
        }

        $path = trim((string)($recipientCertPath ?? ''));
        if ($path === '') {
            return null;
        }

        $pem = @file_get_contents($path);
        if (!is_string($pem) || trim($pem) === '') {
            throw new \RuntimeException('Failed to read recipient certificate PEM from path: ' . $path);
        }
        return $pem;
    }
}
