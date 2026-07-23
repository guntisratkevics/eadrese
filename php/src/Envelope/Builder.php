<?php

declare(strict_types=1);

namespace LatvianEinvoice\Envelope;

use LatvianEinvoice\Attachment;
use LatvianEinvoice\Utils\Crypto;

final class Builder
{
    private static function normalizeMimeType(?string $contentType): string
    {
        $mime = trim((string)($contentType ?? ''));
        if ($mime === '') {
            $mime = 'application/octet-stream';
        }
        return $mime;
    }

    /**
     * @param string[] $recipients
     * @param Attachment[] $attachments
     * @param array<int,array{RecipientE-Address:string,EncryptionInfo?:array{Key:string,CertificateThumbprint:string}}>|null $recipientEntries
     *   Per-recipient transport entries with individual EncryptionInfo. When provided, overrides the
     *   single-key encryptionKeyB64/recipientThumbprintB64 path (mirrors Python's per-recipient flow).
     * @return array{0: array, 1: array|null, 2: string}
     */
    public static function buildEnvelope(
        string $senderEAddress,
        array $recipients,
        string $documentKindCode,
        string $subject,
        string $bodyText,
        array $attachments = [],
        ?string $encryptionKeyB64 = null,
        ?string $recipientThumbprintB64 = null,
        ?string $symmetricKeyBytes = null,
        ?string $symmetricIvBytes = null,
        string $encryptionMode = 'gcm',
        ?string $traceText = 'Created',
        bool $notifySenderOnDelivery = false,
        ?array $recipientEntries = null,
        ?string $referenceId = null
    ): array {
        $now = new \DateTimeImmutable('now', new \DateTimeZone('Europe/Riga'));
        $messageId = bin2hex(random_bytes(16));
        $senderDocId = 'SenderSection';

        $attachmentsInputItems = [];
        $files = [];
        $useCbc = $symmetricKeyBytes !== null && in_array(strtolower($encryptionMode), ['oaep_cbc', 'cbc'], true);
        $cbcIv = $useCbc ? ($symmetricIvBytes ?? random_bytes(16)) : null;

        foreach ($attachments as $idx => $att) {
            // 0-based ContentId/ContentReference — matches Python client and official Java client.
            $contentId = (string)$idx;
            $logicalPayloadBytes = $att->content;
            $payloadBytes = $logicalPayloadBytes;

            if ($symmetricKeyBytes !== null) {
                if ($useCbc) {
                    $payloadBytes = Crypto::encryptPayloadAesCbc($symmetricKeyBytes, $cbcIv, $att->content);
                    $attachmentsInputItems[] = [
                        'ContentId' => $contentId,
                        'Contents' => base64_encode($payloadBytes),
                    ];
                } else {
                    [$iv, $cipherWithTag] = Crypto::encryptPayloadAesGcm($symmetricKeyBytes, $att->content);
                    $payloadBytes = $cipherWithTag;
                    $attachmentsInputItems[] = [
                        'ContentId' => $contentId,
                        'IV' => base64_encode($iv),
                        'CipherText' => base64_encode($cipherWithTag),
                    ];
                }
            } else {
                $attachmentsInputItems[] = [
                    'ContentId' => $contentId,
                    'Contents' => base64_encode($payloadBytes),
                ];
            }

            $digestB64 = base64_encode(hash('sha512', $logicalPayloadBytes, true));
            $files[] = [
                'MimeType' => self::normalizeMimeType($att->contentType),
                'Size' => strlen($logicalPayloadBytes),
                'Name' => $att->filename,
                'Content' => [
                    'ContentReference' => $contentId,
                    'DigestMethod' => ['Algorithm' => 'http://www.w3.org/2001/04/xmlenc#sha512'],
                    'DigestValue' => $digestB64,
                ],
                'Compressed' => false,
                'AppendixNumber' => (string)($idx + 1),
            ];
        }

        $documentKind = [
            'DocumentKindCode' => $documentKindCode,
            'DocumentKindVersion' => '1.0',
        ];
        if ($documentKindCode !== 'DOC_EMPTY') {
            $documentKind['DocumentKindName'] = $documentKindCode;
        }

        $documentMetadata = [
            'GeneralMetadata' => [
                'Authors' => ['AuthorEntry' => [['Institution' => ['Title' => $senderEAddress ?: 'Sender']]]],
                'Date' => $now->format('Y-m-d'),
                'DocumentKind' => $documentKind,
                'Description' => $bodyText,
                'Title' => $subject,
            ],
        ];
        if (!empty($files)) {
            $documentMetadata['PayloadReference'] = ['File' => $files];
        }
        $referenceText = trim((string)($referenceId ?? ''));
        if ($referenceText !== '') {
            $documentMetadata['CommonMetadata'] = [
                'DocumentReferences' => [
                    'ReferenceEntry' => [[
                        'RefRegistrationNumber' => $referenceText,
                    ]],
                ],
            ];
        }

        // Use per-recipient entries when provided (EINVOICE auto-fetch flow); fall back to
        // the legacy single-key path for backwards compatibility.
        if ($recipientEntries === null) {
            $recipientEntries = [];
            foreach ($recipients as $recipient) {
                $entry = ['RecipientE-Address' => $recipient];
                if ($encryptionKeyB64 && $recipientThumbprintB64) {
                    $entry['EncryptionInfo'] = [
                        'Key' => $encryptionKeyB64,
                        'CertificateThumbprint' => $recipientThumbprintB64,
                    ];
                }
                $recipientEntries[] = $entry;
            }
        }

        $senderTransport = [
            'SenderE-Address' => $senderEAddress ?: ($recipients[0] ?? '_DEFAULT@00000000000'),
            'SenderRefNumber' => $messageId,
            'Recipients' => ['RecipientEntry' => $recipientEntries],
            'NotifySenderOnDelivery' => $notifySenderOnDelivery,
            'Priority' => 'normal',
        ];
        if ($traceText) {
            $senderTransport['TraceInfo'] = [
                'TraceInfoEntry' => [[
                    'TraceInfoID' => 'Trace1',
                    'TraceText' => substr($traceText, 0, 50),
                ]],
            ];
        }

        $digestSource = !empty($attachments) ? $attachments[0]->content : $bodyText;
        $digestB64 = base64_encode(hash('sha512', $digestSource, true));
        $signature = [
            'SignedInfo' => [
                'CanonicalizationMethod' => ['Algorithm' => 'http://www.w3.org/2001/10/xml-exc-c14n#'],
                'SignatureMethod' => ['Algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'],
                'Reference' => [
                    'URI' => '#' . $senderDocId,
                    'DigestMethod' => ['Algorithm' => 'http://www.w3.org/2001/04/xmlenc#sha512'],
                    'DigestValue' => $digestB64,
                ],
            ],
            'SignatureValue' => '',
        ];

        $envelope = [
            'SenderDocument' => [
                'Id' => $senderDocId,
                'DocumentMetadata' => $documentMetadata,
                'SenderTransportMetadata' => $senderTransport,
            ],
            'Signatures' => ['Signature' => $signature],
        ];

        $attachmentsInput = !empty($attachmentsInputItems) ? ['AttachmentInput' => $attachmentsInputItems] : null;
        return [$envelope, $attachmentsInput, $messageId];
    }
}
