<?php

declare(strict_types=1);

namespace LatvianEinvoice\Soap;

final class DivMessageSummary
{
    /**
     * Build a convenience summary for GetMessage/GetMessageDecoded responses.
     *
     * @param array<string,mixed> $body
     * @return array<string,mixed>|null
     */
    public static function build(array $body): ?array
    {
        $envelopeXml = $body['EnvelopeXml'] ?? null;
        if (!is_string($envelopeXml) || trim($envelopeXml) === '') {
            return null;
        }

        $doc = new \DOMDocument('1.0', 'utf-8');
        $doc->formatOutput = false;
        $doc->preserveWhiteSpace = false;
        if (!@$doc->loadXML($envelopeXml)) {
            return null;
        }

        $xpath = new \DOMXPath($doc);
        $senderDocEl = $xpath->query('//*[local-name()="SenderDocument"][1]')?->item(0);
        if (!$senderDocEl instanceof \DOMElement) {
            return null;
        }

        $summary = [
            'sender_document_id' => self::elementAttr($senderDocEl, 'Id'),
            'confirmation_name' => self::normalizeNullableString($body['ConfirmationName'] ?? null),
            'document' => [
                'date' => self::xpathString($xpath, './/*[local-name()="GeneralMetadata"][1]/*[local-name()="Date"][1]', $senderDocEl),
                'title' => self::xpathString($xpath, './/*[local-name()="GeneralMetadata"][1]/*[local-name()="Title"][1]', $senderDocEl),
                'description' => self::xpathString($xpath, './/*[local-name()="GeneralMetadata"][1]/*[local-name()="Description"][1]', $senderDocEl),
                'kind' => [
                    'code' => self::xpathString($xpath, './/*[local-name()="DocumentKind"][1]/*[local-name()="DocumentKindCode"][1]', $senderDocEl),
                    'version' => self::xpathString($xpath, './/*[local-name()="DocumentKind"][1]/*[local-name()="DocumentKindVersion"][1]', $senderDocEl),
                    'name' => self::xpathString($xpath, './/*[local-name()="DocumentKind"][1]/*[local-name()="DocumentKindName"][1]', $senderDocEl),
                ],
            ],
            'sender' => [
                'e_address' => self::xpathString($xpath, './/*[local-name()="SenderTransportMetadata"][1]/*[local-name()="SenderE-Address"][1]', $senderDocEl),
                'ref_number' => self::xpathString($xpath, './/*[local-name()="SenderTransportMetadata"][1]/*[local-name()="SenderRefNumber"][1]', $senderDocEl),
                'priority' => self::xpathString($xpath, './/*[local-name()="SenderTransportMetadata"][1]/*[local-name()="Priority"][1]', $senderDocEl),
                'notify_on_delivery' => self::xpathBool($xpath, './/*[local-name()="SenderTransportMetadata"][1]/*[local-name()="NotifySenderOnDelivery"][1]', $senderDocEl),
            ],
            'recipients' => self::extractRecipients($xpath, $senderDocEl, $body),
            'attachments' => self::mergeAttachmentInfo($xpath, $senderDocEl, $body),
        ];

        return self::stripEmptyValues($summary);
    }

    /**
     * @param array<string,mixed> $body
     * @return list<array<string,mixed>>
     */
    private static function extractRecipients(\DOMXPath $xpath, \DOMElement $senderDocEl, array $body): array
    {
        $items = [];
        $recipientNodes = $xpath->query(
            './/*[local-name()="SenderTransportMetadata"][1]//*[local-name()="Recipients"][1]/*[local-name()="RecipientEntry"]',
            $senderDocEl
        );
        if ($recipientNodes) {
            foreach ($recipientNodes as $recipientNode) {
                if (!$recipientNode instanceof \DOMElement) {
                    continue;
                }
                $items[] = self::stripEmptyValues([
                    'e_address' => self::xpathString($xpath, './*[local-name()="RecipientE-Address"][1]', $recipientNode),
                    'encryption' => self::stripEmptyValues([
                        'certificate_thumbprint' => self::xpathString($xpath, './/*[local-name()="EncryptionInfo"][1]/*[local-name()="CertificateThumbprint"][1]', $recipientNode),
                        'has_key' => self::xpathString($xpath, './/*[local-name()="EncryptionInfo"][1]/*[local-name()="Key"][1]', $recipientNode) !== null,
                    ]),
                ]);
            }
        }

        if ($items !== []) {
            return $items;
        }

        $fallback = [];
        $recipients = $body['Recipients'] ?? null;
        if (is_array($recipients)) {
            foreach ($recipients as $recipient) {
                $value = trim((string)$recipient);
                if ($value !== '') {
                    $fallback[] = ['e_address' => $value];
                }
            }
        }
        return $fallback;
    }

    /**
     * @param array<string,mixed> $body
     * @return list<array<string,mixed>>
     */
    private static function mergeAttachmentInfo(\DOMXPath $xpath, \DOMElement $senderDocEl, array $body): array
    {
        $byContentId = [];
        $fileNodes = $xpath->query('.//*[local-name()="PayloadReference"][1]/*[local-name()="File"]', $senderDocEl);
        if ($fileNodes) {
            foreach ($fileNodes as $fileNode) {
                if (!$fileNode instanceof \DOMElement) {
                    continue;
                }
                $contentId = self::xpathString($xpath, './*[local-name()="Content"][1]/*[local-name()="ContentReference"][1]', $fileNode);
                if ($contentId === null) {
                    continue;
                }
                $byContentId[strtolower($contentId)] = self::stripEmptyValues([
                    'content_id' => $contentId,
                    'name' => self::xpathString($xpath, './*[local-name()="Name"][1]', $fileNode),
                    'mime_type' => self::xpathString($xpath, './*[local-name()="MimeType"][1]', $fileNode),
                    'size' => self::xpathInt($xpath, './*[local-name()="Size"][1]', $fileNode),
                    'compressed' => self::xpathBool($xpath, './*[local-name()="Compressed"][1]', $fileNode),
                    'appendix_number' => self::xpathString($xpath, './*[local-name()="AppendixNumber"][1]', $fileNode),
                    'digest' => self::stripEmptyValues([
                        'algorithm' => self::xpathString($xpath, './*[local-name()="Content"][1]/*[local-name()="DigestMethod"][1]/@Algorithm', $fileNode),
                        'value' => self::xpathString($xpath, './*[local-name()="Content"][1]/*[local-name()="DigestValue"][1]', $fileNode),
                    ]),
                ]);
            }
        }

        $attachments = [];
        $attachmentOutput = $body['AttachmentsOutput']['AttachmentOutput'] ?? null;
        if (is_array($attachmentOutput) && array_key_exists('ContentId', $attachmentOutput)) {
            $attachmentOutput = [$attachmentOutput];
        }
        if (!is_array($attachmentOutput)) {
            $attachmentOutput = [];
        }

        foreach ($attachmentOutput as $attachment) {
            if (!is_array($attachment)) {
                continue;
            }
            $contentId = self::normalizeNullableString($attachment['ContentId'] ?? null);
            $key = $contentId !== null ? strtolower($contentId) : null;
            $base = ($key !== null && isset($byContentId[$key]) && is_array($byContentId[$key])) ? $byContentId[$key] : [];
            $contentsB64 = self::normalizeNullableString($attachment['Contents'] ?? null);
            $decrypted = $attachment['DecryptedContent'] ?? null;
            $attachments[] = self::stripEmptyValues(array_merge($base, [
                'content_id' => $contentId,
                'is_separate_call' => is_bool($attachment['IsSeparateCall'] ?? null) ? $attachment['IsSeparateCall'] : null,
                'section_count' => isset($attachment['SectionCount']) && $attachment['SectionCount'] !== null ? (int)$attachment['SectionCount'] : null,
                'section_size' => isset($attachment['SectionSize']) && $attachment['SectionSize'] !== null ? (int)$attachment['SectionSize'] : null,
                'has_contents' => $contentsB64 !== null,
                'contents_len' => $contentsB64 !== null ? self::decodedLengthFromBase64($contentsB64) : null,
                'decrypted_len' => is_string($decrypted) ? strlen($decrypted) : (is_array($decrypted) ? count($decrypted) : null),
                'decrypt_error' => isset($attachment['DecryptError']) ? (bool)$attachment['DecryptError'] : null,
            ]));
            if ($key !== null) {
                unset($byContentId[$key]);
            }
        }

        foreach ($byContentId as $remaining) {
            if (is_array($remaining)) {
                $attachments[] = $remaining;
            }
        }

        return $attachments;
    }

    private static function xpathString(\DOMXPath $xpath, string $expression, ?\DOMNode $contextNode = null): ?string
    {
        $value = trim((string)$xpath->evaluate("string({$expression})", $contextNode));
        return $value !== '' ? $value : null;
    }

    private static function xpathInt(\DOMXPath $xpath, string $expression, ?\DOMNode $contextNode = null): ?int
    {
        $value = self::xpathString($xpath, $expression, $contextNode);
        return $value !== null && is_numeric($value) ? (int)$value : null;
    }

    private static function xpathBool(\DOMXPath $xpath, string $expression, ?\DOMNode $contextNode = null): ?bool
    {
        $value = strtolower(trim((string)$xpath->evaluate("string({$expression})", $contextNode)));
        if ($value === 'true' || $value === '1') {
            return true;
        }
        if ($value === 'false' || $value === '0') {
            return false;
        }
        return null;
    }

    private static function elementAttr(\DOMElement $element, string $name): ?string
    {
        $value = trim($element->getAttribute($name));
        return $value !== '' ? $value : null;
    }

    private static function decodedLengthFromBase64(string $contentsB64): ?int
    {
        $decoded = base64_decode($contentsB64, true);
        return $decoded !== false ? strlen($decoded) : null;
    }

    private static function normalizeNullableString(mixed $value): ?string
    {
        $string = trim((string)$value);
        return $string !== '' ? $string : null;
    }

    /**
     * @param array<string,mixed> $value
     * @return array<string,mixed>
     */
    private static function stripEmptyValues(array $value): array
    {
        foreach ($value as $key => $item) {
            if (is_array($item)) {
                $item = self::stripEmptyValues($item);
                if ($item === []) {
                    unset($value[$key]);
                    continue;
                }
                $value[$key] = $item;
                continue;
            }
            if ($item === null || $item === '') {
                unset($value[$key]);
            }
        }
        return $value;
    }
}
