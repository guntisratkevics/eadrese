<?php

declare(strict_types=1);

use LatvianEinvoice\Config;
use LatvianEinvoice\Soap\DivEnvelopeSigner;
use PHPUnit\Framework\TestCase;

final class DivEnvelopeSignerTest extends TestCase
{
    private const NS_DIV = 'http://ivis.eps.gov.lv/XMLSchemas/100001/DIV/v1-0';
    private const NS_DS = 'http://www.w3.org/2000/09/xmldsig#';
    private const NS_XADES = 'http://uri.etsi.org/01903/v1.3.2#';
    private const NS_C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
    private const NS_EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';

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

    public function test_sign_combined_envelope_is_verifiable(): void
    {
        [$certPem, $keyPem] = $this->generateSelfSigned();

        $tmpDir = sys_get_temp_dir();
        $certPath = tempnam($tmpDir, 'cert_');
        $keyPath = tempnam($tmpDir, 'key_');
        $this->assertIsString($certPath);
        $this->assertIsString($keyPath);
        file_put_contents($certPath, $certPem);
        file_put_contents($keyPath, $keyPem);
        $this->addToAssertionCount(1);

        $cfg = new Config(
            'https://example.invalid/wsdl',
            certificatePath: $certPath,
            privateKeyPath: $keyPath,
            verifySsl: false
        );

        $doc = new DOMDocument('1.0', 'utf-8');
        $doc->formatOutput = false;
        $doc->preserveWhiteSpace = false;

        $root = $doc->createElementNS(self::NS_DIV, 'RecipientConfirmationPart');
        $doc->appendChild($root);

        $sender = $doc->createElementNS(self::NS_DIV, 'SenderDocument');
        $sender->setAttribute('Id', 'SenderSection');
        $root->appendChild($sender);

        $server = $doc->createElementNS(self::NS_DIV, 'ServerTransportMetadata');
        $server->setAttribute('Id', 'ServerSection');
        $root->appendChild($server);

        $confirmations = $doc->createElementNS(self::NS_DIV, 'RecipientConfirmations');
        $root->appendChild($confirmations);
        $entry = $doc->createElementNS(self::NS_DIV, 'ConfirmationEntry');
        $entry->setAttribute('Id', 'ConfirmEntry1');
        $confirmations->appendChild($entry);
        $entry->appendChild($doc->createElementNS(self::NS_DIV, 'Status', 'RecipientAccepted'));

        $root->appendChild($doc->createElementNS(self::NS_DIV, 'Signatures'));

        $sig = DivEnvelopeSigner::signCombinedEnvelope(
            $doc,
            $root,
            $cfg,
            'ConfirmSignature',
            ['SenderSection', 'ServerSection', 'ConfirmEntry1']
        );
        $this->assertSame('Signature', $sig->localName);
        $this->assertSame('ConfirmSignature', $sig->getAttribute('Id'));

        $xpath = new DOMXPath($doc);
        $xpath->registerNamespace('ds', self::NS_DS);
        $xpath->registerNamespace('xades', self::NS_XADES);

        $refs = $xpath->query('.//ds:Reference', $sig);
        $this->assertNotFalse($refs);
        $this->assertGreaterThanOrEqual(4, $refs->length);

        $refByUri = [];
        foreach ($refs as $r) {
            if (!$r instanceof DOMElement) {
                continue;
            }
            $refByUri[(string)$r->getAttribute('URI')] = $r;
        }

        foreach (['#SenderSection', '#ServerSection', '#ConfirmEntry1'] as $uri) {
            $this->assertArrayHasKey($uri, $refByUri);
            $r = $refByUri[$uri];
            $alg = trim((string)$xpath->evaluate('string(.//ds:Transform/@Algorithm)', $r));
            $this->assertSame(self::NS_C14N, $alg);

            $dv = trim((string)$xpath->evaluate('string(.//ds:DigestValue)', $r));
            $this->assertNotSame('', $dv);
        }

        $propsRef = null;
        foreach ($refs as $r) {
            if (!$r instanceof DOMElement) {
                continue;
            }
            if ($r->getAttribute('Type') === 'http://uri.etsi.org/01903#SignedProperties') {
                $propsRef = $r;
                break;
            }
        }
        $this->assertInstanceOf(DOMElement::class, $propsRef);
        $propsAlg = trim((string)$xpath->evaluate('string(.//ds:Transform/@Algorithm)', $propsRef));
        $this->assertSame(self::NS_EXC_C14N, $propsAlg);

        // Verify digest values.
        $b64sha512 = static fn(string $data): string => base64_encode(hash('sha512', $data, true));

        $senderC14n = $sender->C14N(false, false);
        $this->assertNotFalse($senderC14n);
        $senderDv = trim((string)$xpath->evaluate('string(.//ds:DigestValue)', $refByUri['#SenderSection']));
        $this->assertSame($b64sha512($senderC14n), $senderDv);

        $serverC14n = $server->C14N(false, false);
        $this->assertNotFalse($serverC14n);
        $serverDv = trim((string)$xpath->evaluate('string(.//ds:DigestValue)', $refByUri['#ServerSection']));
        $this->assertSame($b64sha512($serverC14n), $serverDv);

        $entryC14n = $entry->C14N(false, false);
        $this->assertNotFalse($entryC14n);
        $entryDv = trim((string)$xpath->evaluate('string(.//ds:DigestValue)', $refByUri['#ConfirmEntry1']));
        $this->assertSame($b64sha512($entryC14n), $entryDv);

        $propsUri = (string)$propsRef->getAttribute('URI');
        $this->assertStringStartsWith('#', $propsUri);
        $propsId = substr($propsUri, 1);
        $propsEl = $xpath->query('.//*[@Id="' . $propsId . '"][1]', $sig)?->item(0);
        $this->assertInstanceOf(DOMElement::class, $propsEl);

        $propsC14n = $propsEl->C14N(true, false);
        $this->assertNotFalse($propsC14n);
        $propsDv = trim((string)$xpath->evaluate('string(.//ds:DigestValue)', $propsRef));
        $this->assertSame($b64sha512($propsC14n), $propsDv);

        // Verify RSA signature over SignedInfo (inclusive C14N).
        $signedInfo = $xpath->query('.//ds:SignedInfo[1]', $sig)?->item(0);
        $this->assertInstanceOf(DOMElement::class, $signedInfo);
        $siC14n = $signedInfo->C14N(false, false);
        $this->assertNotFalse($siC14n);

        $sigValueB64 = trim((string)$xpath->evaluate('string(.//ds:SignatureValue)', $sig));
        $this->assertNotSame('', $sigValueB64);
        $sigRaw = base64_decode($sigValueB64, true);
        $this->assertIsString($sigRaw);

        $pub = openssl_pkey_get_public($certPem);
        $this->assertNotFalse($pub);
        $verifyOk = openssl_verify($siC14n, $sigRaw, $pub, OPENSSL_ALGO_SHA512);
        $this->assertSame(1, $verifyOk);
    }
}

