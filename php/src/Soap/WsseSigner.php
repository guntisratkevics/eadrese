<?php

declare(strict_types=1);

namespace LatvianEinvoice\Soap;

use LatvianEinvoice\Config;
use LatvianEinvoice\Utils\Uuid;

final class WsseSigner
{
    private const NS_SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    private const NS_WSA = 'http://www.w3.org/2005/08/addressing';
    private const NS_WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const NS_WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
    private const NS_DS = 'http://www.w3.org/2000/09/xmldsig#';
    private const NS_EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';

    public static function apply(
        \DOMDocument $doc,
        \DOMElement $soapHeader,
        Config $cfg,
        string $toUrl,
        string $actionUrl
    ): void {
        $soapEnvPrefix = $soapHeader->prefix ?: 'soap-env';

        $actionEl = $doc->createElementNS(self::NS_WSA, 'wsa:Action', $actionUrl);
        $actionEl->setAttributeNS(self::NS_SOAP, $soapEnvPrefix . ':mustUnderstand', 'true');
        $soapHeader->appendChild($actionEl);

        $soapHeader->appendChild($doc->createElementNS(self::NS_WSA, 'wsa:MessageID', 'uuid:' . Uuid::v4()));

        $toId = 'id-' . Uuid::v4();
        $toEl = $doc->createElementNS(self::NS_WSA, 'wsa:To', $toUrl);
        $toEl->setAttributeNS(self::NS_WSU, 'wsu:Id', $toId);
        $soapHeader->appendChild($toEl);

        $securityEl = $doc->createElementNS(self::NS_WSSE, 'wsse:Security');
        $securityEl->setAttributeNS(self::NS_SOAP, $soapEnvPrefix . ':mustUnderstand', 'true');
        $soapHeader->appendChild($securityEl);

        $tsId = 'id-' . Uuid::v4();
        $timestampEl = $doc->createElementNS(self::NS_WSU, 'wsu:Timestamp');
        $timestampEl->setAttributeNS(self::NS_WSU, 'wsu:Id', $tsId);
        $created = gmdate('Y-m-d\\TH:i:s\\Z');
        $expires = gmdate('Y-m-d\\TH:i:s\\Z', time() + 300);
        $timestampEl->appendChild($doc->createElementNS(self::NS_WSU, 'wsu:Created', $created));
        $timestampEl->appendChild($doc->createElementNS(self::NS_WSU, 'wsu:Expires', $expires));
        $securityEl->appendChild($timestampEl);

        if (!$cfg->certificatePath || !$cfg->privateKeyPath) {
            throw new \RuntimeException('WSSE signing requires certificatePath and privateKeyPath');
        }
        $certBytes = file_get_contents($cfg->certificatePath);
        if ($certBytes === false) {
            throw new \RuntimeException('Failed to read certificate: ' . $cfg->certificatePath);
        }
        $bstId = 'BST-' . Uuid::v4();
        $bstEl = $doc->createElementNS(self::NS_WSSE, 'wsse:BinarySecurityToken', self::b64NoNl($certBytes));
        $bstEl->setAttributeNS(self::NS_WSU, 'wsu:Id', $bstId);
        $bstEl->setAttribute('ValueType', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3');
        $bstEl->setAttribute('EncodingType', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary');
        $securityEl->appendChild($bstEl);

        $signatureEl = $doc->createElementNS(self::NS_DS, 'ds:Signature');
        $signedInfoEl = $doc->createElementNS(self::NS_DS, 'ds:SignedInfo');
        $signatureEl->appendChild($signedInfoEl);

        $canonEl = $doc->createElementNS(self::NS_DS, 'ds:CanonicalizationMethod');
        $canonEl->setAttribute('Algorithm', self::NS_EXC_C14N);
        $inclusiveEl = $doc->createElementNS(self::NS_EXC_C14N, 'ec:InclusiveNamespaces');
        $inclusiveEl->setAttribute('PrefixList', 'wsse ' . $soapEnvPrefix);
        $canonEl->appendChild($inclusiveEl);
        $signedInfoEl->appendChild($canonEl);

        $sigMethodEl = $doc->createElementNS(self::NS_DS, 'ds:SignatureMethod');
        $sigMethodEl->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#rsa-sha1');
        $signedInfoEl->appendChild($sigMethodEl);

        $refTsEl = self::addRef($doc, $signedInfoEl, '#' . $tsId);
        self::addC14nTransform($doc, $refTsEl, 'wsu wsse ' . $soapEnvPrefix);

        $refToEl = self::addRef($doc, $signedInfoEl, '#' . $toId);
        self::addC14nTransform($doc, $refToEl, $soapEnvPrefix);

        // Compute digests
        self::setRefDigestSha1B64($refTsEl, self::c14n($timestampEl, true, ['wsu', 'wsse', $soapEnvPrefix]));
        self::setRefDigestSha1B64($refToEl, self::c14n($toEl, true, [$soapEnvPrefix]));

        $sigValueEl = $doc->createElementNS(self::NS_DS, 'ds:SignatureValue');
        $signatureEl->appendChild($sigValueEl);

        $keyInfoEl = $doc->createElementNS(self::NS_DS, 'ds:KeyInfo');
        $strEl = $doc->createElementNS(self::NS_WSSE, 'wsse:SecurityTokenReference');
        $refEl = $doc->createElementNS(self::NS_WSSE, 'wsse:Reference');
        $refEl->setAttribute('URI', '#' . $bstId);
        $refEl->setAttribute('ValueType', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3');
        $strEl->appendChild($refEl);
        $keyInfoEl->appendChild($strEl);
        $signatureEl->appendChild($keyInfoEl);

        $securityEl->appendChild($signatureEl);

        // Sign SignedInfo
        $keyPem = file_get_contents($cfg->privateKeyPath);
        if ($keyPem === false) {
            throw new \RuntimeException('Failed to read private key: ' . $cfg->privateKeyPath);
        }
        $priv = openssl_pkey_get_private($keyPem);
        if ($priv === false) {
            throw new \RuntimeException('Invalid private key PEM');
        }
        $siC14n = self::c14n($signedInfoEl, true, ['wsse', $soapEnvPrefix]);
        $sigRaw = '';
        $ok = openssl_sign($siC14n, $sigRaw, $priv, OPENSSL_ALGO_SHA1);
        openssl_pkey_free($priv);
        if (!$ok) {
            throw new \RuntimeException('Failed to sign WSSE SignedInfo');
        }
        $sigValueEl->nodeValue = base64_encode($sigRaw);

        // Add anonymous ReplyTo/FaultTo like Metro
        $replyToEl = $doc->createElementNS(self::NS_WSA, 'wsa:ReplyTo');
        $replyToEl->appendChild($doc->createElementNS(self::NS_WSA, 'wsa:Address', 'http://www.w3.org/2005/08/addressing/anonymous'));
        $soapHeader->appendChild($replyToEl);
        $faultToEl = $doc->createElementNS(self::NS_WSA, 'wsa:FaultTo');
        $faultToEl->appendChild($doc->createElementNS(self::NS_WSA, 'wsa:Address', 'http://www.w3.org/2005/08/addressing/anonymous'));
        $soapHeader->appendChild($faultToEl);
    }

    private static function addRef(\DOMDocument $doc, \DOMElement $signedInfoEl, string $uri): \DOMElement
    {
        $refEl = $doc->createElementNS(self::NS_DS, 'ds:Reference');
        $refEl->setAttribute('URI', $uri);
        $transformsEl = $doc->createElementNS(self::NS_DS, 'ds:Transforms');
        $refEl->appendChild($transformsEl);

        $digMethodEl = $doc->createElementNS(self::NS_DS, 'ds:DigestMethod');
        $digMethodEl->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#sha1');
        $refEl->appendChild($digMethodEl);
        $refValEl = $doc->createElementNS(self::NS_DS, 'ds:DigestValue');
        $refEl->appendChild($refValEl);

        $signedInfoEl->appendChild($refEl);
        return $refEl;
    }

    private static function addC14nTransform(\DOMDocument $doc, \DOMElement $refEl, string $prefixList): void
    {
        $transformsEl = null;
        foreach ($refEl->childNodes as $child) {
            if ($child instanceof \DOMElement && $child->localName === 'Transforms') {
                $transformsEl = $child;
                break;
            }
        }
        if (!$transformsEl instanceof \DOMElement) {
            $transformsEl = $doc->createElementNS(self::NS_DS, 'ds:Transforms');
            $refEl->insertBefore($transformsEl, $refEl->firstChild);
        }

        $transformEl = $doc->createElementNS(self::NS_DS, 'ds:Transform');
        $transformEl->setAttribute('Algorithm', self::NS_EXC_C14N);
        $inclusiveEl = $doc->createElementNS(self::NS_EXC_C14N, 'ec:InclusiveNamespaces');
        $inclusiveEl->setAttribute('PrefixList', $prefixList);
        $transformEl->appendChild($inclusiveEl);
        $transformsEl->appendChild($transformEl);
    }

    private static function setRefDigestSha1B64(\DOMElement $refEl, string $c14nBytes): void
    {
        $digestB64 = base64_encode(sha1($c14nBytes, true));
        foreach ($refEl->childNodes as $child) {
            if ($child instanceof \DOMElement && $child->localName === 'DigestValue') {
                $child->nodeValue = $digestB64;
                return;
            }
        }
    }

    /**
     * @param string[] $inclusivePrefixes
     */
    private static function c14n(\DOMNode $node, bool $exclusive, array $inclusivePrefixes): string
    {
        if (!($node instanceof \DOMElement)) {
            throw new \RuntimeException('C14N expects DOMElement');
        }
        $c14n = $node->C14N($exclusive, false, null, $inclusivePrefixes);
        if ($c14n === false) {
            throw new \RuntimeException('C14N failed');
        }
        return $c14n;
    }

    private static function b64NoNl(string $bytes): string
    {
        return str_replace(["\r", "\n"], '', base64_encode($bytes));
    }
}
