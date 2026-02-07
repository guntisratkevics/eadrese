<?php

declare(strict_types=1);

namespace LatvianEinvoice\Utils;

final class Pem
{
    public static function toDer(string $pem): string
    {
        $lines = preg_split('/\\r\\n|\\r|\\n/', trim($pem));
        $data = '';
        foreach ($lines as $line) {
            if (str_starts_with($line, '---')) {
                continue;
            }
            $data .= trim($line);
        }
        $der = base64_decode($data, true);
        if ($der === false) {
            throw new \RuntimeException('Failed to decode PEM');
        }
        return $der;
    }

    public static function derBase64(string $pem): string
    {
        return base64_encode(self::toDer($pem));
    }
}

