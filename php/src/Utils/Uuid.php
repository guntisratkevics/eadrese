<?php

declare(strict_types=1);

namespace LatvianEinvoice\Utils;

final class Uuid
{
    public static function v4(): string
    {
        $data = random_bytes(16);
        // Set version to 4
        $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
        // Set variant to RFC 4122
        $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);

        $hex = bin2hex($data);
        return substr($hex, 0, 8) . '-' .
            substr($hex, 8, 4) . '-' .
            substr($hex, 12, 4) . '-' .
            substr($hex, 16, 4) . '-' .
            substr($hex, 20, 12);
    }
}

