<?php

declare(strict_types=1);

namespace LatvianEinvoice\Utils;

final class Crypto
{
    public static function thumbprintSha1B64(string $certPem): string
    {
        $der = self::pemToDer($certPem);
        $digest = sha1($der, true);
        return base64_encode($digest);
    }

    public static function deriveEncryptionFields(string $certPem, ?string $keyBytes = null): array
    {
        $key = $keyBytes ?? random_bytes(32);
        $encKey = self::encryptKeyPkcs1v15($certPem, $key);
        $thumb = self::thumbprintSha1B64($certPem);
        return [$encKey, $thumb, $key];
    }

    public static function deriveEncryptionFieldsOaepCbc(string $certPem, ?string $keyBytes = null, ?string $ivBytes = null): array
    {
        $key = $keyBytes ?? random_bytes(32);
        $iv = $ivBytes ?? random_bytes(16);
        $blob = self::buildDivKeyBlob($key, $iv);
        $encKey = self::encryptKeyOaepSha1($certPem, $blob);
        $thumb = self::thumbprintSha1B64($certPem);
        return [$encKey, $thumb, $key, $iv];
    }

    public static function encryptKeyPkcs1v15(string $certPem, string $keyBytes): string
    {
        $pub = openssl_pkey_get_public($certPem);
        if ($pub === false) {
            throw new \RuntimeException('Invalid certificate PEM');
        }
        $ok = openssl_public_encrypt($keyBytes, $encrypted, $pub, OPENSSL_PKCS1_PADDING);
        if (!$ok) {
            throw new \RuntimeException('Failed to encrypt key');
        }
        return base64_encode($encrypted);
    }

    public static function encryptKeyOaepSha1(string $certPem, string $keyBytes): string
    {
        $pub = openssl_pkey_get_public($certPem);
        if ($pub === false) {
            throw new \RuntimeException('Invalid certificate PEM');
        }
        $ok = openssl_public_encrypt($keyBytes, $encrypted, $pub, OPENSSL_PKCS1_OAEP_PADDING);
        if (!$ok) {
            throw new \RuntimeException('Failed to encrypt key');
        }
        return base64_encode($encrypted);
    }

    public static function encryptPayloadAesGcm(string $key, string $plaintext, string $aad = ''): array
    {
        $iv = random_bytes(12);
        $tag = '';
        $cipher = self::cipherForKey(strlen($key), 'gcm');
        $ct = openssl_encrypt($plaintext, $cipher, $key, OPENSSL_RAW_DATA, $iv, $tag, $aad, 16);
        if ($ct === false) {
            throw new \RuntimeException('Failed to encrypt payload');
        }
        return [$iv, $ct . $tag];
    }

    public static function encryptPayloadAesCbc(string $key, string $iv, string $plaintext): string
    {
        $cipher = self::cipherForKey(strlen($key), 'cbc');
        $pt = self::pkcs7Pad($plaintext, 16);
        $ct = openssl_encrypt($pt, $cipher, $key, OPENSSL_RAW_DATA, $iv);
        if ($ct === false) {
            throw new \RuntimeException('Failed to encrypt payload');
        }
        return $ct;
    }

    public static function decryptDivKey(string $privateKeyPem, string $encKeyB64): array
    {
        $priv = openssl_pkey_get_private($privateKeyPem);
        if ($priv === false) {
            throw new \RuntimeException('Invalid private key PEM');
        }
        $enc = base64_decode($encKeyB64);
        $ok = openssl_private_decrypt($enc, $raw, $priv, OPENSSL_PKCS1_OAEP_PADDING);
        if (!$ok || $raw === null || $raw === '') {
            throw new \RuntimeException('Failed to decrypt DIV key');
        }
        if (strlen($raw) < 4) {
            throw new \RuntimeException('Invalid key blob size');
        }
        $keyLen = unpack('N', substr($raw, 0, 4))[1];
        if (!in_array($keyLen, [16, 24, 32], true)) {
            throw new \RuntimeException('Unexpected AES key length');
        }
        if (strlen($raw) < 4 + $keyLen + 16) {
            throw new \RuntimeException('Invalid key blob size');
        }
        $key = substr($raw, 4, $keyLen);
        $iv = substr($raw, 4 + $keyLen);
        if (strlen($iv) !== 16) {
            throw new \RuntimeException('Invalid IV length');
        }
        return [$key, $iv];
    }

    public static function decryptPayloadAesCbc(string $key, string $iv, string $ciphertext): string
    {
        $cipher = self::cipherForKey(strlen($key), 'cbc');
        $pt = openssl_decrypt($ciphertext, $cipher, $key, OPENSSL_RAW_DATA, $iv);
        if ($pt === false) {
            throw new \RuntimeException('Failed to decrypt payload');
        }
        return $pt;
    }

    private static function buildDivKeyBlob(string $key, string $iv): string
    {
        return pack('N', strlen($key)) . $key . $iv;
    }

    private static function pkcs7Pad(string $data, int $blockSize): string
    {
        $pad = $blockSize - (strlen($data) % $blockSize);
        return $data . str_repeat(chr($pad), $pad);
    }

    private static function cipherForKey(int $keyLen, string $mode): string
    {
        return match ($keyLen) {
            16 => 'aes-128-' . $mode,
            24 => 'aes-192-' . $mode,
            32 => 'aes-256-' . $mode,
            default => throw new \RuntimeException('Unsupported AES key length'),
        };
    }

    private static function pemToDer(string $pem): string
    {
        $lines = preg_split('/\r\n|\r|\n/', trim($pem));
        $data = '';
        foreach ($lines as $line) {
            if (str_starts_with($line, '---')) {
                continue;
            }
            $data .= trim($line);
        }
        $der = base64_decode($data);
        if ($der === false) {
            throw new \RuntimeException('Failed to parse certificate');
        }
        return $der;
    }
}
