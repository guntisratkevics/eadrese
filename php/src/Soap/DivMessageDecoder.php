<?php

declare(strict_types=1);

namespace LatvianEinvoice\Soap;

use LatvianEinvoice\Config;
use LatvianEinvoice\Utils\Crypto;

/**
 * Helpers for decoding UnifiedServiceInterface GetMessage/GetAttachmentSection responses:
 * - stitch attachment sections (IsSeparateCall=true)
 * - decrypt DIV AES-CBC payloads (RSA-OAEP(SHA1) wrapped key blob)
 * - optional GZIP decompression when SenderDocument marks File.Compressed=true
 */
final class DivMessageDecoder
{
    /**
     * @param array<string,mixed> $body Parsed GetMessage body (DirectSoapClient::tryParseGetMessageResponse output).
     */
    public static function stitchAttachmentSections(DirectSoapClient $soap, string $messageId, array &$body): void
    {
        $attachmentsOutput = $body['AttachmentsOutput'] ?? null;
        if (!is_array($attachmentsOutput)) {
            return;
        }
        $attachments = $attachmentsOutput['AttachmentOutput'] ?? null;
        if (!is_array($attachments)) {
            return;
        }

        // Normalize to list.
        if (array_key_exists('ContentId', $attachments)) {
            $attachments = [$attachments];
        }

        foreach ($attachments as $idx => $att) {
            if (!is_array($att)) {
                continue;
            }
            $isSeparate = $att['IsSeparateCall'] ?? null;
            if ($isSeparate !== true) {
                continue;
            }
            $contentId = isset($att['ContentId']) ? (string)$att['ContentId'] : '';
            $sectionCount = (int)($att['SectionCount'] ?? 0);
            if ($contentId === '' || $sectionCount <= 0) {
                continue;
            }
            $combined = '';
            for ($i = 0; $i < $sectionCount; $i++) {
                $sec = $soap->getAttachmentSection($messageId, $contentId, $i);
                $secBody = is_array($sec['body'] ?? null) ? $sec['body'] : null;
                $partB64 = is_array($secBody) ? ($secBody['Contents'] ?? null) : null;
                if (!is_string($partB64) || $partB64 === '') {
                    continue;
                }
                $bytes = base64_decode($partB64, true);
                if ($bytes === false) {
                    continue;
                }
                $combined .= $bytes;
            }
            if ($combined !== '') {
                $att['Contents'] = base64_encode($combined);
                $attachments[$idx] = $att;
            }
        }

        $body['AttachmentsOutput']['AttachmentOutput'] = $attachments;
    }

    /**
     * Decrypts `AttachmentsOutput.AttachmentOutput[].Contents` into `DecryptedContent` when possible.
     *
     * @param array<string,mixed> $body Parsed GetMessage body (DirectSoapClient::tryParseGetMessageResponse output).
     */
    public static function decryptAttachments(array &$body, Config $cfg): void
    {
        $envelopeXml = $body['EnvelopeXml'] ?? null;
        if (!is_string($envelopeXml) || trim($envelopeXml) === '') {
            return;
        }
        if (!$cfg->privateKeyPath || !is_file($cfg->privateKeyPath)) {
            return;
        }

        $privPem = file_get_contents($cfg->privateKeyPath);
        if ($privPem === false) {
            return;
        }

        $certThumb = null;
        if ($cfg->certificatePath && is_file($cfg->certificatePath)) {
            $certPem = file_get_contents($cfg->certificatePath);
            if ($certPem !== false) {
                $certThumb = trim(Crypto::thumbprintSha1B64($certPem));
            }
        }

        $envDoc = new \DOMDocument('1.0', 'utf-8');
        $envDoc->formatOutput = false;
        $envDoc->preserveWhiteSpace = false;
        if (!@$envDoc->loadXML($envelopeXml)) {
            return;
        }
        $xpath = new \DOMXPath($envDoc);

        $fileMap = self::payloadFileMap($xpath);
        $candidates = self::encryptionCandidates($xpath);
        if (!$candidates) {
            return;
        }
        if ($certThumb !== null && $certThumb !== '') {
            usort($candidates, static fn(array $a, array $b): int => ($a['thumb'] === $certThumb ? 0 : 1) <=> ($b['thumb'] === $certThumb ? 0 : 1));
        }

        $aesKey = null;
        $aesIv = null;
        foreach ($candidates as $cand) {
            try {
                [$k, $iv] = Crypto::decryptDivKey($privPem, (string)$cand['key']);
                $aesKey = $k;
                $aesIv = $iv;
                break;
            } catch (\Throwable) {
                continue;
            }
        }

        $gcmKey = null;
        if ($aesKey === null) {
            foreach ($candidates as $cand) {
                try {
                    $raw = Crypto::decryptKeyPkcs1v15($privPem, (string)$cand['key']);
                    if ($raw !== '' && in_array(strlen($raw), [16, 24, 32], true)) {
                        $gcmKey = $raw;
                        break;
                    }
                } catch (\Throwable) {
                    continue;
                }
            }
        }

        $attachmentsOutput = $body['AttachmentsOutput'] ?? null;
        if (!is_array($attachmentsOutput)) {
            return;
        }
        $attachments = $attachmentsOutput['AttachmentOutput'] ?? null;
        if (!is_array($attachments)) {
            return;
        }
        if (array_key_exists('ContentId', $attachments)) {
            $attachments = [$attachments];
        }

        foreach ($attachments as $idx => $att) {
            if (!is_array($att)) {
                continue;
            }
            if (array_key_exists('DecryptedContent', $att)) {
                continue;
            }
            $contentId = isset($att['ContentId']) ? (string)$att['ContentId'] : '';
            $contentsB64 = isset($att['Contents']) ? (string)$att['Contents'] : '';
            if ($contentsB64 === '') {
                continue;
            }
            $cipherBytes = base64_decode($contentsB64, true);
            if ($cipherBytes === false) {
                $att['DecryptError'] = true;
                $attachments[$idx] = $att;
                continue;
            }

            $meta = $contentId !== '' ? ($fileMap[strtolower($contentId)] ?? null) : null;
            if (is_array($meta) && empty($att['Name']) && !empty($meta['Name'])) {
                $att['Name'] = (string)$meta['Name'];
            }
            $compressed = is_array($meta) ? (bool)($meta['Compressed'] ?? false) : false;

            $ok = false;
            if ($aesKey !== null && $aesIv !== null) {
                try {
                    $pt = Crypto::decryptPayloadAesCbc($aesKey, $aesIv, $cipherBytes);
                    if ($compressed) {
                        $pt2 = @gzdecode($pt);
                        if ($pt2 !== false) {
                            $pt = $pt2;
                        }
                    }
                    $att['DecryptedContent'] = $pt;
                    $ok = true;
                } catch (\Throwable) {
                    $ok = false;
                }
            }

            if (!$ok && $gcmKey !== null) {
                try {
                    $iv = substr($cipherBytes, 0, 12);
                    $ct = substr($cipherBytes, 12);
                    $pt = Crypto::decryptPayloadAesGcm($gcmKey, $iv, $ct);
                    if ($compressed) {
                        $pt2 = @gzdecode($pt);
                        if ($pt2 !== false) {
                            $pt = $pt2;
                        }
                    }
                    $att['DecryptedContent'] = $pt;
                    $ok = true;
                } catch (\Throwable) {
                    $ok = false;
                }
            }

            if (!$ok) {
                $att['DecryptError'] = true;
            }
            $attachments[$idx] = $att;
        }

        $body['AttachmentsOutput']['AttachmentOutput'] = $attachments;
    }

    /**
     * @return array<string,array{Name:?string,Compressed:bool}>
     */
    private static function payloadFileMap(\DOMXPath $xpath): array
    {
        $out = [];
        $nodes = $xpath->query('//*[local-name()="PayloadReference"]//*[local-name()="File"]');
        if (!$nodes) {
            return $out;
        }
        foreach ($nodes as $fileEl) {
            if (!$fileEl instanceof \DOMElement) {
                continue;
            }
            $contentRef = trim((string)$xpath->evaluate('string(./*[local-name()="Content"][1]/*[local-name()="ContentReference"][1])', $fileEl));
            if ($contentRef === '') {
                continue;
            }
            $name = trim((string)$xpath->evaluate('string(./*[local-name()="Name"][1])', $fileEl));
            $compressedRaw = strtolower(trim((string)$xpath->evaluate('string(./*[local-name()="Compressed"][1])', $fileEl)));
            $compressed = $compressedRaw === 'true' || $compressedRaw === '1';
            $out[strtolower($contentRef)] = [
                'Name' => $name !== '' ? $name : null,
                'Compressed' => $compressed,
            ];
        }
        return $out;
    }

    /**
     * @return array<int,array{key:string,thumb:string}>
     */
    private static function encryptionCandidates(\DOMXPath $xpath): array
    {
        $out = [];
        $nodes = $xpath->query('//*[local-name()="RecipientEntry"]//*[local-name()="EncryptionInfo"]');
        if (!$nodes) {
            return $out;
        }
        foreach ($nodes as $encEl) {
            if (!$encEl instanceof \DOMElement) {
                continue;
            }
            $key = trim((string)$xpath->evaluate('string(./*[local-name()="Key"][1])', $encEl));
            if ($key === '') {
                continue;
            }
            $thumb = trim((string)$xpath->evaluate('string(./*[local-name()="CertificateThumbprint"][1])', $encEl));
            $out[] = ['key' => $key, 'thumb' => $thumb];
        }
        return $out;
    }
}

