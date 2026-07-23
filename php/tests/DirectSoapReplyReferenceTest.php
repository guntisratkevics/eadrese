<?php

declare(strict_types=1);

use LatvianEinvoice\Soap\DirectSoapClient;
use PHPUnit\Framework\TestCase;

final class DirectSoapReplyReferenceTest extends TestCase
{
    public function test_reply_reference_uses_div_namespace_and_escapes_text(): void
    {
        [$document, $metadata] = $this->newDocumentMetadata();

        $method = new ReflectionMethod(DirectSoapClient::class, 'appendReplyReference');
        $method->setAccessible(true);
        $method->invoke(null, $document, $metadata, '  MESSAGE-&-001  ');

        $xpath = new DOMXPath($document);
        $xpath->registerNamespace('div', 'http://ivis.eps.gov.lv/XMLSchemas/100001/DIV/v1-0');
        $reference = $xpath->query(
            '/div:DocumentMetadata/div:CommonMetadata/div:DocumentReferences'
            . '/div:ReferenceEntry/div:RefRegistrationNumber'
        )?->item(0);

        $this->assertInstanceOf(DOMElement::class, $reference);
        $this->assertSame('MESSAGE-&-001', $reference->textContent);
        $this->assertStringContainsString('MESSAGE-&amp;-001', $document->saveXML());
    }

    public function test_blank_reply_reference_is_omitted(): void
    {
        [$document, $metadata] = $this->newDocumentMetadata();

        $method = new ReflectionMethod(DirectSoapClient::class, 'appendReplyReference');
        $method->setAccessible(true);
        $method->invoke(null, $document, $metadata, '   ');

        $this->assertSame(0, $metadata->childNodes->length);
    }

    /**
     * @return array{DOMDocument, DOMElement}
     */
    private function newDocumentMetadata(): array
    {
        $document = new DOMDocument('1.0', 'utf-8');
        $metadata = $document->createElementNS(
            'http://ivis.eps.gov.lv/XMLSchemas/100001/DIV/v1-0',
            'DocumentMetadata'
        );
        $document->appendChild($metadata);

        return [$document, $metadata];
    }
}
