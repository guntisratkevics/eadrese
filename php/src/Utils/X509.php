<?php

declare(strict_types=1);

namespace LatvianEinvoice\Utils;

final class X509
{
    /**
     * @return array<string,mixed>
     */
    public static function parse(string $certPem): array
    {
        $cert = openssl_x509_read($certPem);
        if ($cert === false) {
            throw new \RuntimeException('Invalid certificate PEM');
        }
        $parsed = openssl_x509_parse($cert);
        if (!is_array($parsed)) {
            throw new \RuntimeException('Failed to parse certificate');
        }
        return $parsed;
    }

    public static function certDerB64(string $certPem): string
    {
        return Pem::derBase64($certPem);
    }

    public static function certSha1B64(string $certPem): string
    {
        $der = Pem::toDer($certPem);
        return base64_encode(sha1($der, true));
    }

    /**
     * @return array{0:string,1:string} base64(Modulus), base64(Exponent)
     */
    public static function rsaModExpB64(string $certPem): array
    {
        $pub = openssl_pkey_get_public($certPem);
        if ($pub === false) {
            throw new \RuntimeException('Invalid certificate public key');
        }
        $details = openssl_pkey_get_details($pub);
        if (!is_array($details) || !isset($details['rsa']) || !is_array($details['rsa'])) {
            throw new \RuntimeException('Unsupported public key type (expected RSA)');
        }
        $rsa = $details['rsa'];
        $n = $rsa['n'] ?? null;
        $e = $rsa['e'] ?? null;
        if (!is_string($n) || !is_string($e)) {
            throw new \RuntimeException('Invalid RSA key details');
        }
        return [base64_encode($n), base64_encode($e)];
    }

    public static function issuerName(array $parsed): string
    {
        $issuer = $parsed['issuer'] ?? [];
        return self::dnToString(is_array($issuer) ? $issuer : [], ['CN', 'DC', 'O', 'OU', 'C']);
    }

    public static function subjectName(array $parsed): string
    {
        $subject = $parsed['subject'] ?? [];
        return self::dnToString(is_array($subject) ? $subject : [], ['CN', 'OU', 'O', 'C', 'DC']);
    }

    public static function serialNumber(array $parsed): string
    {
        $sn = $parsed['serialNumber'] ?? null;
        if ($sn === null) {
            return '';
        }
        return is_string($sn) ? $sn : (string)$sn;
    }

    /**
     * @param array<string, mixed> $dn
     * @param string[] $preferredOrder
     */
    private static function dnToString(array $dn, array $preferredOrder): string
    {
        $parts = [];
        $used = [];

        $append = function (string $key) use (&$parts, &$used, $dn): void {
            if (!array_key_exists($key, $dn)) {
                return;
            }
            $value = $dn[$key];
            $used[$key] = true;
            if (is_array($value)) {
                // Approximate RFC4514 ordering (most OpenSSL decoders don't preserve full RDN order).
                // In practice DIV expects DC values in reverse order vs openssl_x509_parse output.
                $vals = array_reverse(array_values($value));
                foreach ($vals as $v) {
                    if ($v === null || $v === '') {
                        continue;
                    }
                    $parts[] = $key . '=' . (string)$v;
                }
                return;
            }
            if ($value === null || $value === '') {
                return;
            }
            $parts[] = $key . '=' . (string)$value;
        };

        foreach ($preferredOrder as $key) {
            $append($key);
        }

        foreach ($dn as $key => $value) {
            if (isset($used[$key])) {
                continue;
            }
            if (is_array($value)) {
                $vals = array_reverse(array_values($value));
                foreach ($vals as $v) {
                    if ($v === null || $v === '') {
                        continue;
                    }
                    $parts[] = $key . '=' . (string)$v;
                }
                continue;
            }
            if ($value === null || $value === '') {
                continue;
            }
            $parts[] = $key . '=' . (string)$value;
        }

        return implode(', ', $parts);
    }
}
