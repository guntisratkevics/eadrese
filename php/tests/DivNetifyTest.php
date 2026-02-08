<?php

declare(strict_types=1);

use LatvianEinvoice\Soap\DivNetify;
use PHPUnit\Framework\TestCase;

final class DivNetifyTest extends TestCase
{
    private const NS_DIV = 'http://ivis.eps.gov.lv/XMLSchemas/100001/DIV/v1-0';
    private const NS_ADDR = 'http://ivis.eps.gov.lv/XMLSchemas/100001/Address/v1-1';

    public function test_netify_rewrites_address_lva_children_to_address_namespace(): void
    {
        if (!class_exists(XSLTProcessor::class)) {
            $this->markTestSkipped('ext-xsl not available');
        }

        $doc = new DOMDocument('1.0', 'utf-8');
        $doc->formatOutput = false;
        $doc->preserveWhiteSpace = false;

        $root = $doc->createElementNS(self::NS_DIV, 'cm:AddressLVA');
        $doc->appendChild($root);

        $street = $doc->createElementNS(self::NS_DIV, 'cm:Street', 'Riga');
        $root->appendChild($street);

        $out = DivNetify::netifyElement($root);
        $this->assertSame('AddressLVA', $out->localName);

        $streetOut = $out->getElementsByTagNameNS(self::NS_ADDR, 'Street')?->item(0);
        $this->assertInstanceOf(DOMElement::class, $streetOut);
        $this->assertSame('Riga', trim((string)$streetOut->textContent));
    }
}

