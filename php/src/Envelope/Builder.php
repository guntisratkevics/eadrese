<?php

declare(strict_types=1);

namespace LatvianEinvoice\Envelope;

use LatvianEinvoice\Attachment;
use LatvianEinvoice\Utils\Crypto;

final class Builder
{
    /**
     * @param string[] $recipients
     * @param Attachment[] $attachments
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
        bool $notifySenderOnDelivery = false
    ): array {
        $now = new \DateTimeImmutable('now', new \DateTimeZone('Europe/Riga'));
        $messageId = bin2hex(random_bytes(16));
        $senderDocId = 'SenderSection';

        $attachmentsInputItems = [];
        $files = [];
        $useCbc = $symmetricKeyBytes !== null && in_array(strtolower($encryptionMode), ['oaep_cbc', 'cbc'], true);
        $cbcIv = $useCbc ? ($symmetricIvBytes ?? random_bytes(16)) : null;

        foreach ($attachments as $idx => $att) {
            $contentId = (string)$idx;
            $payloadBytes = $att->content;

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

            $digestB64 = base64_encode(hash('sha512', $payloadBytes, true));
            $files[] = [
                'MimeType' => $att->contentType,
                'Size' => strlen($payloadBytes),
                'Name' => $att->filename,
                'Content' => [
                    'ContentReference' => $contentId,
                    'DigestMethod' => ['Algorithm' => 'http://www.w3.org/2001/04/xmlenc#sha512'],
                    'DigestValue' => $digestB64,
                ],
                'Compressed' => false,
                'AppendixNumber' => '1',
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
                'Title' => $subject,
                'Description' => $bodyText,
                'DocumentKind' => $documentKind,
            ],
        ];
        if (!empty($files)) {
            $documentMetadata['PayloadReference'] = ['File' => $files];
        }

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
