<?php

declare(strict_types=1);

use LatvianEinvoice\Utils\Crypto;
use PHPUnit\Framework\TestCase;

final class CryptoTest extends TestCase
{
    /**
     * @return array{0:string,1:string} cert PEM, private key PEM
     */
    private function generateSelfSigned(): array
    {
        $priv = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048,
        ]);
        $this->assertNotFalse($priv);

        $csr = openssl_csr_new(['commonName' => 'test.example'], $priv, ['digest_alg' => 'sha256']);
        $this->assertNotFalse($csr);

        $x509 = openssl_csr_sign($csr, null, $priv, 1, ['digest_alg' => 'sha256']);
        $this->assertNotFalse($x509);

        $certPem = '';
        $this->assertTrue(openssl_x509_export($x509, $certPem));
        $keyPem = '';
        $this->assertTrue(openssl_pkey_export($priv, $keyPem));

        return [$certPem, $keyPem];
    }

    public function test_oaep_cbc_key_blob_roundtrip(): void
    {
        [$certPem, $keyPem] = $this->generateSelfSigned();

        $key = str_repeat("\x01", 32);
        $iv = str_repeat("\x02", 16);

        [$encKeyB64, $thumbB64, $symKey, $symIv] = Crypto::deriveEncryptionFieldsOaepCbc($certPem, $key, $iv);
        $this->assertSame($key, $symKey);
        $this->assertSame($iv, $symIv);
        $this->assertNotSame('', $encKeyB64);
        $this->assertNotSame('', $thumbB64);

        [$decKey, $decIv] = Crypto::decryptDivKey($keyPem, $encKeyB64);
        $this->assertSame($key, $decKey);
        $this->assertSame($iv, $decIv);
    }

    public function test_aes_cbc_roundtrip(): void
    {
        $key = str_repeat("\x03", 32);
        $iv = str_repeat("\x04", 16);
        $pt = "hello world";

        $ct = Crypto::encryptPayloadAesCbc($key, $iv, $pt);
        $dec = Crypto::decryptPayloadAesCbc($key, $iv, $ct);

        $this->assertSame($pt, $dec);
    }
}

