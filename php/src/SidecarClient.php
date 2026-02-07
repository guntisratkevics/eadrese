<?php

declare(strict_types=1);

namespace LatvianEinvoice;

final class SidecarClient
{
    private string $baseUrl;

    public function __construct(string $baseUrl)
    {
        $this->baseUrl = rtrim($baseUrl, '/');
    }

    /**
     * @return array{status:int, body:array|null, raw:string}
     */
    public function sendTextMessage(
        string $connectionId,
        string $recipient,
        string $subject,
        string $body = '',
        bool $unsigned = false
    ): array {
        $payload = [
            'connection_id' => $connectionId,
            'recipient_regno' => $recipient,
            'subject' => $subject,
            'body' => $body,
            'unsigned' => $unsigned,
        ];
        return $this->requestJson('POST', '/api/send-message', $payload);
    }

    /**
     * @return array{status:int, body:array|null, raw:string}
     */
    public function sendInvoice(
        string $connectionId,
        string $recipient,
        string $filePath,
        string $subject,
        string $description = '',
        ?string $filename = null,
        ?string $mimeType = null,
        ?string $vidSubaddress = null,
        bool $unsigned = false
    ): array {
        if (!is_file($filePath)) {
            throw new \RuntimeException('Missing invoice file: ' . $filePath);
        }
        $meta = [
            'connection_id' => $connectionId,
            'recipient_regno' => $recipient,
            'vid_subaddress' => $vidSubaddress,
            'subject' => $subject,
            'description' => $description,
            'filename' => $filename,
            'mime_type' => $mimeType,
            'unsigned' => $unsigned,
        ];

        $curlFile = new \CURLFile(
            $filePath,
            $mimeType ?: 'application/octet-stream',
            $filename ?: basename($filePath)
        );

        $fields = [
            'meta' => json_encode($meta, JSON_UNESCAPED_SLASHES),
            'file' => $curlFile,
        ];

        return $this->requestMultipart('POST', '/api/send-invoice', $fields);
    }

    /**
     * @return array{status:int, body:array|null, raw:string}
     */
    public function listMessages(string $connectionId, int $limit = 50): array
    {
        $limit = max(1, min(200, $limit));
        $query = http_build_query([
            'connection_id' => $connectionId,
            'limit' => (string)$limit,
        ]);
        return $this->requestRaw('GET', '/api/messages?' . $query, null, []);
    }

    /**
     * @return array{status:int, body:array|null, raw:string}
     */
    public function confirmMessage(string $connectionId, string $messageId): array
    {
        $payload = ['connection_id' => $connectionId];
        return $this->requestJson('POST', '/api/messages/' . rawurlencode($messageId) . '/confirm', $payload);
    }

    /**
     * @param array<string,mixed> $payload
     * @return array{status:int, body:array|null, raw:string}
     */
    private function requestJson(string $method, string $path, array $payload): array
    {
        $body = json_encode($payload, JSON_UNESCAPED_SLASHES);
        return $this->requestRaw($method, $path, $body, ['Content-Type: application/json']);
    }

    /**
     * @param array<string,mixed> $fields
     * @return array{status:int, body:array|null, raw:string}
     */
    private function requestMultipart(string $method, string $path, array $fields): array
    {
        $url = $this->baseUrl . $path;
        $ch = curl_init($url);
        if ($ch === false) {
            throw new \RuntimeException('Failed to init cURL');
        }
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $fields);

        $raw = curl_exec($ch);
        if ($raw === false) {
            $err = curl_error($ch);
            curl_close($ch);
            throw new \RuntimeException('cURL error: ' . $err);
        }
        $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        $decoded = json_decode($raw, true);
        return ['status' => $status, 'body' => is_array($decoded) ? $decoded : null, 'raw' => $raw];
    }

    /**
     * @param string[] $headers
     * @return array{status:int, body:array|null, raw:string}
     */
    private function requestRaw(string $method, string $path, ?string $body, array $headers): array
    {
        $url = $this->baseUrl . $path;
        $ch = curl_init($url);
        if ($ch === false) {
            throw new \RuntimeException('Failed to init cURL');
        }
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        if (!empty($headers)) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        }
        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        $raw = curl_exec($ch);
        if ($raw === false) {
            $err = curl_error($ch);
            curl_close($ch);
            throw new \RuntimeException('cURL error: ' . $err);
        }
        $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        $decoded = json_decode($raw, true);
        return ['status' => $status, 'body' => is_array($decoded) ? $decoded : null, 'raw' => $raw];
    }
}
