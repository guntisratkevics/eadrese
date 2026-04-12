<?php

declare(strict_types=1);

namespace LatvianEinvoice\Soap;

use LatvianEinvoice\Config;
use LatvianEinvoice\Utils\X509;

final class DivEnvelopeSigner
{
    private const NS_DIV = 'http://ivis.eps.gov.lv/XMLSchemas/100001/DIV/v1-0';
    private const NS_DS = 'http://www.w3.org/2000/09/xmldsig#';
    private const NS_XADES = 'http://uri.etsi.org/01903/v1.3.2#';
    private const NS_C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
    private const NS_EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    private const XADES_QP_PREFIX = 'QualifyingProperties';

    public static function signEnvelope(\DOMDocument $doc, \DOMElement $divEnvelope, Config $cfg): void
    {
        if (!$cfg->certificatePath || !$cfg->privateKeyPath) {
            throw new \RuntimeException('DIV signing requires certificatePath and privateKeyPath');
        }
        $certPem = file_get_contents($cfg->certificatePath);
        if ($certPem === false) {
            throw new \RuntimeException('Failed to read certificate: ' . $cfg->certificatePath);
        }
        $keyPem = file_get_contents($cfg->privateKeyPath);
        if ($keyPem === false) {
            throw new \RuntimeException('Failed to read private key: ' . $cfg->privateKeyPath);
        }
        $priv = openssl_pkey_get_private($keyPem);
        if ($priv === false) {
            throw new \RuntimeException('Invalid private key PEM');
        }

        $x509Parsed = X509::parse($certPem);
        [$modB64, $expB64] = X509::rsaModExpB64($certPem);
        $certDerB64 = X509::certDerB64($certPem);
        $certSha1B64 = X509::certSha1B64($certPem);
        $issuerName = X509::issuerName($x509Parsed);
        $subjectName = X509::subjectName($x509Parsed);
        $serial = X509::serialNumber($x509Parsed);

        $senderDoc = self::firstChildByLocalName($divEnvelope, 'SenderDocument');
        if (!$senderDoc instanceof \DOMElement) {
            throw new \RuntimeException('Missing SenderDocument');
        }
        $senderDocId = $senderDoc->getAttribute('Id');
        if ($senderDocId === '') {
            throw new \RuntimeException('SenderDocument missing Id attribute');
        }

        $signaturesEl = self::firstChildByLocalName($divEnvelope, 'Signatures');
        if (!$signaturesEl instanceof \DOMElement) {
            $signaturesEl = $doc->createElementNS(self::NS_DIV, 'Signatures');
            $divEnvelope->appendChild($signaturesEl);
        } else {
            while ($signaturesEl->firstChild) {
                $signaturesEl->removeChild($signaturesEl->firstChild);
            }
        }

        $signatureId = 'SenderSignature';
        $signedPropsId = 'ds-SignedProperties';
        $signatureValueId = 'ds-SignatureValue';

        $sigEl = $doc->createElementNS(self::NS_DS, 'ds:Signature');
        $sigEl->setAttribute('Id', $signatureId);
        $signaturesEl->appendChild($sigEl);

        $signedInfoEl = $doc->createElementNS(self::NS_DS, 'ds:SignedInfo');
        $sigEl->appendChild($signedInfoEl);

        $canonEl = $doc->createElementNS(self::NS_DS, 'ds:CanonicalizationMethod');
        $canonEl->setAttribute('Algorithm', self::NS_C14N);
        $signedInfoEl->appendChild($canonEl);

        $sigMethodEl = $doc->createElementNS(self::NS_DS, 'ds:SignatureMethod');
        $sigMethodEl->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512');
        $signedInfoEl->appendChild($sigMethodEl);

        $refSender = $doc->createElementNS(self::NS_DS, 'ds:Reference');
        $refSender->setAttribute('URI', '#' . $senderDocId);
        $transforms = $doc->createElementNS(self::NS_DS, 'ds:Transforms');
        $transform = $doc->createElementNS(self::NS_DS, 'ds:Transform');
        // Use exclusive C14N for SenderDocument — matches the Python reference client and the official Java
        // client behaviour (confirmed in latvian_einvoice/soap/client.py: EXCL_C14N for SenderDoc digest).
        // Inclusive C14N here caused PSS.045 rejections because namespace contamination from ancestor
        // elements (SOAP, UUI) differs between signing context and VRAA verification context.
        $transform->setAttribute('Algorithm', self::NS_EXC_C14N);
        $transforms->appendChild($transform);
        $refSender->appendChild($transforms);
        $dm = $doc->createElementNS(self::NS_DS, 'ds:DigestMethod');
        $dm->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha512');
        $refSender->appendChild($dm);
        $dvSender = $doc->createElementNS(self::NS_DS, 'ds:DigestValue');
        $refSender->appendChild($dvSender);
        $signedInfoEl->appendChild($refSender);

        // Reference: SignedProperties
        // No <ds:Transforms> element — matches official Java client and Python client output.
        // VRAA verifies the digest against the raw serialization of the SignedProperties element.
        // Despite no declared transform, we compute the digest with exclusive C14N (ds prefix in scope)
        // to match the Python client: etree.tostring(signed_props, method="c14n", exclusive=True,
        // inclusive_ns_prefixes=["ds"]).
        $refSp = $doc->createElementNS(self::NS_DS, 'ds:Reference');
        $refSp->setAttribute('URI', '#' . $signedPropsId);
        $refSp->setAttribute('Type', 'http://uri.etsi.org/01903#SignedProperties');
        $dm2 = $doc->createElementNS(self::NS_DS, 'ds:DigestMethod');
        $dm2->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha512');
        $refSp->appendChild($dm2);
        $dvSp = $doc->createElementNS(self::NS_DS, 'ds:DigestValue');
        $refSp->appendChild($dvSp);
        $signedInfoEl->appendChild($refSp);

        $sigValueEl = $doc->createElementNS(self::NS_DS, 'ds:SignatureValue');
        $sigValueEl->setAttribute('Id', $signatureValueId);
        $sigEl->appendChild($sigValueEl);

        $keyInfoEl = $doc->createElementNS(self::NS_DS, 'ds:KeyInfo');
        $keyInfoEl->setAttribute('Id', 'ds-KeyInfo');
        $sigEl->appendChild($keyInfoEl);

        $keyValueEl = $doc->createElementNS(self::NS_DS, 'ds:KeyValue');
        $rsaKeyValueEl = $doc->createElementNS(self::NS_DS, 'ds:RSAKeyValue');
        $rsaKeyValueEl->appendChild($doc->createElementNS(self::NS_DS, 'ds:Modulus', $modB64));
        $rsaKeyValueEl->appendChild($doc->createElementNS(self::NS_DS, 'ds:Exponent', $expB64));
        $keyValueEl->appendChild($rsaKeyValueEl);
        $keyInfoEl->appendChild($keyValueEl);

        $x509DataEl = $doc->createElementNS(self::NS_DS, 'ds:X509Data');
        $x509DataEl->appendChild($doc->createElementNS(self::NS_DS, 'ds:X509Certificate', $certDerB64));
        if ($subjectName !== '') {
            $x509DataEl->appendChild($doc->createElementNS(self::NS_DS, 'ds:X509SubjectName', $subjectName));
        }
        if ($issuerName !== '' && $serial !== '') {
            $issuerSerial2El = $doc->createElementNS(self::NS_DS, 'ds:X509IssuerSerial');
            $issuerSerial2El->appendChild($doc->createElementNS(self::NS_DS, 'ds:X509IssuerName', $issuerName));
            $issuerSerial2El->appendChild($doc->createElementNS(self::NS_DS, 'ds:X509SerialNumber', $serial));
            $x509DataEl->appendChild($issuerSerial2El);
        }
        $keyInfoEl->appendChild($x509DataEl);

        $objEl = $doc->createElementNS(self::NS_DS, 'ds:Object');
        $sigEl->appendChild($objEl);

        $qpEl = $doc->createElementNS(self::NS_XADES, 'QualifyingProperties');
        $qpEl->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns', self::NS_XADES);
        $qpEl->setAttribute('Target', '#' . $signatureId);
        $qpEl->setAttribute('Id', 'ds-QualifyingProperties');
        $objEl->appendChild($qpEl);

        $spEl = $doc->createElementNS(self::NS_XADES, 'SignedProperties');
        $spEl->setAttribute('Id', $signedPropsId);
        $qpEl->appendChild($spEl);

        $sspEl = $doc->createElementNS(self::NS_XADES, 'SignedSignatureProperties');
        $spEl->appendChild($sspEl);

        $signingTime = new \DateTimeImmutable('now');
        $signingTimeEl = $doc->createElementNS(self::NS_XADES, 'SigningTime', $signingTime->format('Y-m-d\\TH:i:sP'));
        $sspEl->appendChild($signingTimeEl);

        $scEl = $doc->createElementNS(self::NS_XADES, 'SigningCertificate');
        $sspEl->appendChild($scEl);
        $certEl = $doc->createElementNS(self::NS_XADES, 'Cert');
        $scEl->appendChild($certEl);

        $certDigestEl = $doc->createElementNS(self::NS_XADES, 'CertDigest');
        $certEl->appendChild($certDigestEl);
        $dmSha1 = $doc->createElementNS(self::NS_DS, 'ds:DigestMethod');
        $dmSha1->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#sha1');
        $certDigestEl->appendChild($dmSha1);
        $dvSha1 = $doc->createElementNS(self::NS_DS, 'ds:DigestValue', $certSha1B64);
        $certDigestEl->appendChild($dvSha1);

        $issuerSerialEl = $doc->createElementNS(self::NS_XADES, 'IssuerSerial');
        $certEl->appendChild($issuerSerialEl);
        $issuerNameEl = $doc->createElementNS(self::NS_DS, 'ds:X509IssuerName', $issuerName);
        $issuerSerialEl->appendChild($issuerNameEl);
        $serialEl = $doc->createElementNS(self::NS_DS, 'ds:X509SerialNumber', $serial);
        $issuerSerialEl->appendChild($serialEl);

        $senderC14n = self::c14n($senderDoc, true, []);
        $dvSender->nodeValue = base64_encode(hash('sha512', $senderC14n, true));

        $spC14n = self::c14n($spEl, false, []);
        $dvSp->nodeValue = base64_encode(hash('sha512', $spC14n, true));

        $siC14n = self::c14n($signedInfoEl, false, []);
        $sigRaw = '';
        $ok = openssl_sign($siC14n, $sigRaw, $priv, OPENSSL_ALGO_SHA512);
        if (!$ok) {
            throw new \RuntimeException('Failed to sign DIV SignedInfo');
        }
        $sigValueEl->nodeValue = base64_encode($sigRaw);
    }

    /**
     * @param string[] $signedSectionIds
     */
    public static function signCombinedEnvelope(
        \DOMDocument $doc,
        \DOMElement $combinedRoot,
        Config $cfg,
        string $signatureId,
        array $signedSectionIds,
        array $sectionDigestHints = []
    ): \DOMElement {
        if (!$cfg->certificatePath || !$cfg->privateKeyPath) {
            throw new \RuntimeException('DIV signing requires certificatePath and privateKeyPath');
        }
        $certPem = file_get_contents($cfg->certificatePath);
        if ($certPem === false) {
            throw new \RuntimeException('Failed to read certificate: ' . $cfg->certificatePath);
        }
        $keyPem = file_get_contents($cfg->privateKeyPath);
        if ($keyPem === false) {
            throw new \RuntimeException('Failed to read private key: ' . $cfg->privateKeyPath);
        }
        $priv = openssl_pkey_get_private($keyPem);
        if ($priv === false) {
            throw new \RuntimeException('Invalid private key PEM');
        }

        $x509Parsed = X509::parse($certPem);
        [$modB64, $expB64] = X509::rsaModExpB64($certPem);
        $certDerB64 = X509::certDerB64($certPem);
        $certSha1B64 = X509::certSha1B64($certPem);
        $issuerName = X509::issuerName($x509Parsed);
        $subjectName = X509::subjectName($x509Parsed);
        $serial = X509::serialNumber($x509Parsed);

        $signaturesEl = self::firstChildByLocalName($combinedRoot, 'Signatures');
        if (!$signaturesEl instanceof \DOMElement) {
            $signaturesEl = $doc->createElementNS(self::NS_DIV, 'Signatures');
            $combinedRoot->appendChild($signaturesEl);
        }

        foreach ($signedSectionIds as $sectionId) {
            $sectionId = (string)$sectionId;
            if ($sectionId === '') {
                continue;
            }
            $found = self::findElementById($combinedRoot, $sectionId);
            if (!$found instanceof \DOMElement) {
                throw new \RuntimeException('Missing signed section: ' . $sectionId);
            }
        }

        $signedPropsId = 'ds-SignedProperties';
        $signatureValueId = 'ds-SignatureValue';

        $sigEl = $doc->createElementNS(self::NS_DS, 'ds:Signature');
        $sigEl->setAttribute('Id', $signatureId);
        $signaturesEl->appendChild($sigEl);

        $signedInfoEl = $doc->createElementNS(self::NS_DS, 'ds:SignedInfo');
        $sigEl->appendChild($signedInfoEl);

        $canonEl = $doc->createElementNS(self::NS_DS, 'ds:CanonicalizationMethod');
        $canonEl->setAttribute('Algorithm', self::NS_C14N);
        $signedInfoEl->appendChild($canonEl);

        $sigMethodEl = $doc->createElementNS(self::NS_DS, 'ds:SignatureMethod');
        $sigMethodEl->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512');
        $signedInfoEl->appendChild($sigMethodEl);

        $sectionDigestNodes = [];
        foreach ($signedSectionIds as $sectionId) {
            $sectionId = (string)$sectionId;
            if ($sectionId === '') {
                continue;
            }
            $ref = $doc->createElementNS(self::NS_DS, 'ds:Reference');
            $ref->setAttribute('URI', '#' . $sectionId);

            $transforms = $doc->createElementNS(self::NS_DS, 'ds:Transforms');
            $transform = $doc->createElementNS(self::NS_DS, 'ds:Transform');
            $transform->setAttribute('Algorithm', self::NS_C14N);
            $transforms->appendChild($transform);
            $ref->appendChild($transforms);

            $dm = $doc->createElementNS(self::NS_DS, 'ds:DigestMethod');
            $dm->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha512');
            $ref->appendChild($dm);

            $dv = $doc->createElementNS(self::NS_DS, 'ds:DigestValue');
            $ref->appendChild($dv);

            $signedInfoEl->appendChild($ref);
            $sectionDigestNodes[$sectionId] = $dv;
        }

        $refSp = $doc->createElementNS(self::NS_DS, 'ds:Reference');
        $refSp->setAttribute('URI', '#' . $signedPropsId);
        $refSp->setAttribute('Type', 'http://uri.etsi.org/01903#SignedProperties');
        $spTransforms = $doc->createElementNS(self::NS_DS, 'ds:Transforms');
        $spTransform = $doc->createElementNS(self::NS_DS, 'ds:Transform');
        $spTransform->setAttribute('Algorithm', self::NS_EXC_C14N);
        $spTransforms->appendChild($spTransform);
        $refSp->appendChild($spTransforms);
        $dm2 = $doc->createElementNS(self::NS_DS, 'ds:DigestMethod');
        $dm2->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha512');
        $refSp->appendChild($dm2);
        $dvSp = $doc->createElementNS(self::NS_DS, 'ds:DigestValue');
        $refSp->appendChild($dvSp);
        $signedInfoEl->appendChild($refSp);

        $sigValueEl = $doc->createElementNS(self::NS_DS, 'ds:SignatureValue');
        $sigValueEl->setAttribute('Id', $signatureValueId);
        $sigEl->appendChild($sigValueEl);

        $keyInfoEl = $doc->createElementNS(self::NS_DS, 'ds:KeyInfo');
        $keyInfoEl->setAttribute('Id', 'ds-KeyInfo');
        $sigEl->appendChild($keyInfoEl);

        $keyValueEl = $doc->createElementNS(self::NS_DS, 'ds:KeyValue');
        $rsaKeyValueEl = $doc->createElementNS(self::NS_DS, 'ds:RSAKeyValue');
        $rsaKeyValueEl->appendChild($doc->createElementNS(self::NS_DS, 'ds:Modulus', $modB64));
        $rsaKeyValueEl->appendChild($doc->createElementNS(self::NS_DS, 'ds:Exponent', $expB64));
        $keyValueEl->appendChild($rsaKeyValueEl);
        $keyInfoEl->appendChild($keyValueEl);

        $x509DataEl = $doc->createElementNS(self::NS_DS, 'ds:X509Data');
        $x509DataEl->appendChild($doc->createElementNS(self::NS_DS, 'ds:X509Certificate', $certDerB64));
        if ($subjectName !== '') {
            $x509DataEl->appendChild($doc->createElementNS(self::NS_DS, 'ds:X509SubjectName', $subjectName));
        }
        if ($issuerName !== '' && $serial !== '') {
            $issuerSerial2El = $doc->createElementNS(self::NS_DS, 'ds:X509IssuerSerial');
            $issuerSerial2El->appendChild($doc->createElementNS(self::NS_DS, 'ds:X509IssuerName', $issuerName));
            $issuerSerial2El->appendChild($doc->createElementNS(self::NS_DS, 'ds:X509SerialNumber', $serial));
            $x509DataEl->appendChild($issuerSerial2El);
        }
        $keyInfoEl->appendChild($x509DataEl);

        $objEl = $doc->createElementNS(self::NS_DS, 'ds:Object');
        $sigEl->appendChild($objEl);

        $qpEl = $doc->createElementNS(self::NS_XADES, 'QualifyingProperties');
        $qpEl->setAttribute('Target', '#' . $signatureId);
        $qpEl->setAttribute('Id', 'ds-QualifyingProperties');
        $objEl->appendChild($qpEl);

        $spEl = $doc->createElementNS(self::NS_XADES, 'SignedProperties');
        $spEl->setAttribute('Id', $signedPropsId);
        $qpEl->appendChild($spEl);

        $sspEl = $doc->createElementNS(self::NS_XADES, 'SignedSignatureProperties');
        $spEl->appendChild($sspEl);

        $signingTimeEl = $doc->createElementNS(self::NS_XADES, 'SigningTime', gmdate('Y-m-d\\TH:i:sP'));
        $sspEl->appendChild($signingTimeEl);

        $scEl = $doc->createElementNS(self::NS_XADES, 'SigningCertificate');
        $sspEl->appendChild($scEl);
        $certEl = $doc->createElementNS(self::NS_XADES, 'Cert');
        $scEl->appendChild($certEl);

        $certDigestEl = $doc->createElementNS(self::NS_XADES, 'CertDigest');
        $certEl->appendChild($certDigestEl);
        $dmSha1El = $doc->createElementNS(self::NS_DS, 'ds:DigestMethod');
        $dmSha1El->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#sha1');
        $certDigestEl->appendChild($dmSha1El);
        $dvSha1El = $doc->createElementNS(self::NS_DS, 'ds:DigestValue', $certSha1B64);
        $certDigestEl->appendChild($dvSha1El);

        $issuerSerialEl = $doc->createElementNS(self::NS_XADES, 'IssuerSerial');
        $certEl->appendChild($issuerSerialEl);
        $issuerNameEl = $doc->createElementNS(self::NS_DS, 'ds:X509IssuerName', $issuerName);
        $issuerSerialEl->appendChild($issuerNameEl);
        $serialEl = $doc->createElementNS(self::NS_DS, 'ds:X509SerialNumber', $serial);
        $issuerSerialEl->appendChild($serialEl);

        foreach ($signedSectionIds as $sectionId) {
            $sectionId = (string)$sectionId;
            if ($sectionId === '') {
                continue;
            }
            $target = self::findElementById($combinedRoot, $sectionId);
            if (!$target instanceof \DOMElement) {
                throw new \RuntimeException('Missing signed section: ' . $sectionId);
            }
            $c14n = self::c14n($target, true, []);
            $computedDigest = base64_encode(hash('sha512', $c14n, true));
            $hintedDigest = trim((string)($sectionDigestHints[$sectionId] ?? ''));
            $digest = ($hintedDigest !== '' && $hintedDigest === $computedDigest)
                ? $hintedDigest
                : $computedDigest;

            $sectionDigestNodes[$sectionId]->nodeValue = self::wrapDigestText($digest);
        }

        $spC14n = self::c14n($spEl, true, ['ds']);
        $dvSp->nodeValue = self::wrapDigestText(base64_encode(hash('sha512', $spC14n, true)));

        $xpath = new \DOMXPath($doc);
        $xpath->registerNamespace('ds', self::NS_DS);
        $digestNodes = $xpath->query('.//ds:DigestValue', $sigEl);
        if ($digestNodes) {
            foreach ($digestNodes as $digestNode) {
                if ($digestNode instanceof \DOMElement) {
                    $digestNode->nodeValue = self::wrapDigestText((string)$digestNode->nodeValue);
                }
            }
        }

        $siC14n = self::c14n($signedInfoEl, false, []);
        $sigRaw = '';
        $ok = openssl_sign($siC14n, $sigRaw, $priv, OPENSSL_ALGO_SHA512);
        if (!$ok) {
            throw new \RuntimeException('Failed to sign DIV SignedInfo');
        }
        $sigValueEl->nodeValue = base64_encode($sigRaw);

        return $sigEl;
    }

    public static function resignSignatureValueInContext(
        \DOMElement $signature,
        Config $cfg,
        bool $refreshAllReferences = true
    ): void {
        if (!$cfg->privateKeyPath) {
            throw new \RuntimeException('DIV signing requires privateKeyPath');
        }

        $keyPem = file_get_contents($cfg->privateKeyPath);
        if ($keyPem === false) {
            throw new \RuntimeException('Failed to read private key: ' . $cfg->privateKeyPath);
        }
        $priv = openssl_pkey_get_private($keyPem);
        if ($priv === false) {
            throw new \RuntimeException('Invalid private key PEM');
        }

        $signedInfo = self::firstChildByLocalName($signature, 'SignedInfo');
        $sigValue = self::firstChildByLocalName($signature, 'SignatureValue');
        if (!$signedInfo instanceof \DOMElement || !$sigValue instanceof \DOMElement) {
            return;
        }

        self::refreshReferenceDigestsInContext($signature, !$refreshAllReferences);

        $siC14n = self::c14n($signedInfo, false, []);
        $sigRaw = '';
        $ok = openssl_sign($siC14n, $sigRaw, $priv, OPENSSL_ALGO_SHA512);
        if (!$ok) {
            throw new \RuntimeException('Failed to sign DIV SignedInfo');
        }
        $sigValue->nodeValue = base64_encode($sigRaw);
    }

    public static function refreshReferenceDigestsInContext(
        \DOMElement $signature,
        bool $signedPropertiesOnly = false
    ): void {
        $doc = $signature->ownerDocument;
        if (!$doc instanceof \DOMDocument || !$doc->documentElement instanceof \DOMElement) {
            return;
        }

        $xpath = new \DOMXPath($doc);
        $xpath->registerNamespace('ds', self::NS_DS);
        $refs = $xpath->query('./ds:SignedInfo/ds:Reference', $signature);
        if (!$refs) {
            return;
        }

        foreach ($refs as $ref) {
            if (!$ref instanceof \DOMElement) {
                continue;
            }
            $uri = trim((string)$ref->getAttribute('URI'));
            if (!str_starts_with($uri, '#')) {
                continue;
            }
            $targetId = substr($uri, 1);
            if (!is_string($targetId) || $targetId === '') {
                continue;
            }
            $target = self::findElementById($doc->documentElement, $targetId);
            if (!$target instanceof \DOMElement) {
                continue;
            }

            $type = trim((string)$ref->getAttribute('Type'));
            if ($signedPropertiesOnly && $type !== 'http://uri.etsi.org/01903#SignedProperties') {
                continue;
            }
            $c14n = $type === 'http://uri.etsi.org/01903#SignedProperties'
                ? self::c14n($target, true, ['ds'])
                : self::c14n($target, true, []);
            $digest = self::wrapDigestText(base64_encode(hash('sha512', $c14n, true)));

            $dv = $xpath->query('./ds:DigestValue[1]', $ref)?->item(0);
            if ($dv instanceof \DOMElement) {
                $dv->nodeValue = $digest;
            }
        }
    }

    private static function firstChildByLocalName(\DOMElement $parent, string $localName): ?\DOMElement
    {
        foreach ($parent->childNodes as $child) {
            if ($child instanceof \DOMElement && $child->localName === $localName) {
                return $child;
            }
        }
        return null;
    }

    private static function findElementById(\DOMElement $root, string $id): ?\DOMElement
    {
        if ($root->getAttribute('Id') === $id) {
            return $root;
        }
        foreach ($root->getElementsByTagName('*') as $child) {
            if ($child instanceof \DOMElement && $child->getAttribute('Id') === $id) {
                return $child;
            }
        }
        return null;
    }

    /**
     * @param string[] $inclusivePrefixes
     */
    private static function c14n(\DOMElement $el, bool $exclusive, array $inclusivePrefixes): string
    {
        $prefixes = $exclusive && !empty($inclusivePrefixes) ? $inclusivePrefixes : null;
        $c14n = $el->C14N($exclusive, false, null, $prefixes);
        if ($c14n === false) {
            throw new \RuntimeException('C14N failed');
        }
        return $c14n;
    }

    private static function wrapDigestText(string $value): string
    {
        $text = trim($value);
        if ($text === '' || str_contains($text, "\n")) {
            return $text;
        }
        if (strlen($text) <= 76) {
            return $text;
        }
        return implode("\n", str_split($text, 76));
    }
}
