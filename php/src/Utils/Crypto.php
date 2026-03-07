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

    public static function encryptKeyOaepSha1FromModExp(
        string $modulusB64,
        string $exponentB64,
        string $keyBytes
    ): string {
        $pem = self::rsaPublicKeyPemFromModExp($modulusB64, $exponentB64);
        return self::encryptKeyOaepSha1($pem, $keyBytes);
    }

    public static function buildDivKeyBlob(string $key, string $iv): string
    {
        if (!in_array(strlen($key), [16, 24, 32], true)) {
            throw new \RuntimeException('Unsupported AES key length');
        }
        if (strlen($iv) !== 16) {
            throw new \RuntimeException('Invalid IV length');
        }
        return chr(strlen($key)) . $key . $iv;
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
        $ct = openssl_encrypt($pt, $cipher, $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
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
        // Java/.NET DIV key blob format: 1-byte key length + key bytes + 16-byte IV.
        if (strlen($raw) < 1 + 16 + 16) {
            throw new \RuntimeException('Invalid key blob size');
        }
        $keyLen = ord($raw[0]);
        if (!in_array($keyLen, [16, 24, 32], true)) {
            throw new \RuntimeException('Unexpected AES key length');
        }
        if (strlen($raw) < 1 + $keyLen + 16) {
            throw new \RuntimeException('Invalid key blob size');
        }
        $key = substr($raw, 1, $keyLen);
        $iv = substr($raw, 1 + $keyLen, 16);
        if (strlen($iv) !== 16) {
            throw new \RuntimeException('Invalid IV length');
        }
        return [$key, $iv];
    }

    public static function decryptKeyPkcs1v15(string $privateKeyPem, string $encKeyB64): string
    {
        $priv = openssl_pkey_get_private($privateKeyPem);
        if ($priv === false) {
            throw new \RuntimeException('Invalid private key PEM');
        }
        $enc = base64_decode($encKeyB64, true);
        if ($enc === false) {
            throw new \RuntimeException('Invalid base64 encrypted key');
        }
        $ok = openssl_private_decrypt($enc, $raw, $priv, OPENSSL_PKCS1_PADDING);
        if (!$ok || $raw === null) {
            throw new \RuntimeException('Failed to decrypt key (PKCS1v15)');
        }
        return (string)$raw;
    }

    public static function decryptPayloadAesGcm(string $key, string $iv, string $ciphertextWithTag, string $aad = ''): string
    {
        if (strlen($ciphertextWithTag) < 16) {
            throw new \RuntimeException('Ciphertext is too short (missing GCM tag)');
        }
        $tag = substr($ciphertextWithTag, -16);
        $ct = substr($ciphertextWithTag, 0, -16);
        $cipher = self::cipherForKey(strlen($key), 'gcm');
        $pt = openssl_decrypt($ct, $cipher, $key, OPENSSL_RAW_DATA, $iv, $tag, $aad);
        if ($pt === false) {
            throw new \RuntimeException('Failed to decrypt payload');
        }
        return $pt;
    }

    public static function decryptPayloadAesCbc(string $key, string $iv, string $ciphertext): string
    {
        $cipher = self::cipherForKey(strlen($key), 'cbc');
        $pt = openssl_decrypt($ciphertext, $cipher, $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
        if ($pt === false) {
            throw new \RuntimeException('Failed to decrypt payload');
        }
        return self::pkcs7Unpad($pt, 16);
    }

    private static function rsaPublicKeyPemFromModExp(string $modulusB64, string $exponentB64): string
    {
        $modulus = base64_decode(trim($modulusB64), true);
        $exponent = base64_decode(trim($exponentB64), true);
        if (!is_string($modulus) || $modulus === '' || !is_string($exponent) || $exponent === '') {
            throw new \RuntimeException('Invalid RSA modulus/exponent encoding');
        }

        $rsaPublicKey = self::derEncodeSequence(
            self::derEncodeInteger($modulus) .
            self::derEncodeInteger($exponent)
        );
        $algorithmId = self::derEncodeSequence(
            self::derEncodeOid('1.2.840.113549.1.1.1') .
            self::derEncodeNull()
        );
        $subjectPublicKeyInfo = self::derEncodeSequence(
            $algorithmId .
            self::derEncodeBitString($rsaPublicKey)
        );

        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($subjectPublicKeyInfo), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    private static function derEncodeInteger(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");
        if ($bytes === '') {
            $bytes = "\x00";
        }
        if ((ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00" . $bytes;
        }
        return "\x02" . self::derEncodeLength(strlen($bytes)) . $bytes;
    }

    private static function derEncodeSequence(string $content): string
    {
        return "\x30" . self::derEncodeLength(strlen($content)) . $content;
    }

    private static function derEncodeBitString(string $bytes): string
    {
        $content = "\x00" . $bytes;
        return "\x03" . self::derEncodeLength(strlen($content)) . $content;
    }

    private static function derEncodeNull(): string
    {
        return "\x05\x00";
    }

    private static function derEncodeOid(string $oid): string
    {
        $parts = array_map('intval', explode('.', $oid));
        if (count($parts) < 2) {
            throw new \RuntimeException('Invalid OID');
        }
        $first = array_shift($parts);
        $second = array_shift($parts);
        $encoded = chr($first * 40 + $second);
        foreach ($parts as $part) {
            if ($part < 0) {
                throw new \RuntimeException('Invalid OID part');
            }
            $stack = [chr($part & 0x7F)];
            $part >>= 7;
            while ($part > 0) {
                array_unshift($stack, chr(($part & 0x7F) | 0x80));
                $part >>= 7;
            }
            $encoded .= implode('', $stack);
        }
        return "\x06" . self::derEncodeLength(strlen($encoded)) . $encoded;
    }

    private static function derEncodeLength(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }
        $bytes = '';
        $value = $length;
        while ($value > 0) {
            $bytes = chr($value & 0xFF) . $bytes;
            $value >>= 8;
        }
        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    private static function pkcs7Pad(string $data, int $blockSize): string
    {
        $pad = $blockSize - (strlen($data) % $blockSize);
        return $data . str_repeat(chr($pad), $pad);
    }

    private static function pkcs7Unpad(string $data, int $blockSize): string
    {
        $len = strlen($data);
        if ($len === 0 || ($len % $blockSize) !== 0) {
            throw new \RuntimeException('Invalid padded data length');
        }
        $pad = ord($data[$len - 1]);
        if ($pad <= 0 || $pad > $blockSize) {
            throw new \RuntimeException('Invalid PKCS7 padding');
        }
        // Validate padding bytes.
        for ($i = 0; $i < $pad; $i++) {
            if (ord($data[$len - 1 - $i]) !== $pad) {
                throw new \RuntimeException('Invalid PKCS7 padding');
            }
        }
        return substr($data, 0, $len - $pad);
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
