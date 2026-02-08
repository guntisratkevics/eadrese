<?php

declare(strict_types=1);

use LatvianEinvoice\Soap\DirectSoapClient;
use PHPUnit\Framework\TestCase;

final class MtomParsingTest extends TestCase
{
    public function test_try_parse_get_message_response_extracts_xop_include_contents(): void
    {
        $boundary = 'uuid:boundary123';
        $soapXml = <<<XML
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:uui="http://vraa.gov.lv/xmlschemas/div/uui/2011/11"
               xmlns:cm="http://ivis.eps.gov.lv/XMLSchemas/100001/DIV/v1-0"
               xmlns:xop="http://www.w3.org/2004/08/xop/include">
  <soap:Body>
    <uui:GetMessageOutput>
      <cm:Envelope>
        <cm:SenderDocument Id="SenderSection" />
        <cm:ServerTransportMetadata Id="ServerSection" />
      </cm:Envelope>
      <uui:Recipients>
        <uui:string>_PRIVATE@RECIP</uui:string>
      </uui:Recipients>
      <uui:ConfirmationName>CONF</uui:ConfirmationName>
      <uui:AttachmentsOutput>
        <uui:AttachmentOutput>
          <uui:ContentId>file1</uui:ContentId>
          <uui:IsSeparateCall>false</uui:IsSeparateCall>
          <uui:Contents><xop:Include href="cid:att1"/></uui:Contents>
        </uui:AttachmentOutput>
      </uui:AttachmentsOutput>
    </uui:GetMessageOutput>
  </soap:Body>
</soap:Envelope>
XML;

        $raw = '';
        $raw .= "--{$boundary}\r\n";
        $raw .= "Content-Type: application/xop+xml; charset=UTF-8; type=\"application/soap+xml\"\r\n";
        $raw .= "Content-Transfer-Encoding: 8bit\r\n";
        $raw .= "Content-ID: <rootpart>\r\n";
        $raw .= "\r\n";
        $raw .= $soapXml . "\r\n";
        $raw .= "--{$boundary}\r\n";
        $raw .= "Content-Type: application/octet-stream\r\n";
        $raw .= "Content-Transfer-Encoding: base64\r\n";
        $raw .= "Content-ID: <att1>\r\n";
        $raw .= "\r\n";
        $raw .= base64_encode('Hello') . "\r\n";
        $raw .= "--{$boundary}--\r\n";

        $m = new ReflectionMethod(DirectSoapClient::class, 'tryParseGetMessageResponse');
        $m->setAccessible(true);
        $parsed = $m->invoke(null, $raw);

        $this->assertIsArray($parsed);
        $this->assertArrayHasKey('AttachmentsOutput', $parsed);
        $this->assertIsArray($parsed['AttachmentsOutput']);
        $att = $parsed['AttachmentsOutput']['AttachmentOutput'][0] ?? null;
        $this->assertIsArray($att);
        $this->assertSame('file1', $att['ContentId']);
        $this->assertSame('SGVsbG8=', $att['Contents']);
    }
}

