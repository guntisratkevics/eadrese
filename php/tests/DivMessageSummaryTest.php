<?php

declare(strict_types=1);

use LatvianEinvoice\Soap\DivMessageSummary;
use PHPUnit\Framework\TestCase;

final class DivMessageSummaryTest extends TestCase
{
    public function test_build_merges_envelope_metadata_with_attachment_output(): void
    {
        $envelopeXml = <<<'XML'
<cm:Envelope xmlns:cm="http://ivis.eps.gov.lv/XMLSchemas/100001/DIV/v1-0">
  <cm:SenderDocument Id="SenderSection">
    <cm:DocumentMetadata>
      <cm:GeneralMetadata>
        <cm:Date>2026-04-10</cm:Date>
        <cm:DocumentKind>
          <cm:DocumentKindCode>EINVOICE</cm:DocumentKindCode>
          <cm:DocumentKindVersion>1.0</cm:DocumentKindVersion>
          <cm:DocumentKindName>EINVOICE</cm:DocumentKindName>
        </cm:DocumentKind>
        <cm:Description>Please see attachment</cm:Description>
        <cm:Title>Invoice INV-001</cm:Title>
      </cm:GeneralMetadata>
      <cm:PayloadReference>
        <cm:File>
          <cm:MimeType>application/xml</cm:MimeType>
          <cm:Size>6014</cm:Size>
          <cm:Name>invoice.xml</cm:Name>
          <cm:Content>
            <cm:ContentReference>file-1</cm:ContentReference>
            <cm:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
            <cm:DigestValue>abc123=</cm:DigestValue>
          </cm:Content>
          <cm:Compressed>false</cm:Compressed>
          <cm:AppendixNumber>1</cm:AppendixNumber>
        </cm:File>
      </cm:PayloadReference>
    </cm:DocumentMetadata>
    <cm:SenderTransportMetadata>
      <cm:SenderE-Address>_PRIVATE@SENDER_EXAMPLE</cm:SenderE-Address>
      <cm:SenderRefNumber>MSG-123</cm:SenderRefNumber>
      <cm:NotifySenderOnDelivery>true</cm:NotifySenderOnDelivery>
      <cm:Priority>normal</cm:Priority>
      <cm:Recipients>
        <cm:RecipientEntry>
          <cm:RecipientE-Address>_PRIVATE@RECIPIENT_EXAMPLE</cm:RecipientE-Address>
          <cm:EncryptionInfo>
            <cm:CertificateThumbprint>thumb-1</cm:CertificateThumbprint>
            <cm:Key>key-1</cm:Key>
          </cm:EncryptionInfo>
        </cm:RecipientEntry>
      </cm:Recipients>
    </cm:SenderTransportMetadata>
  </cm:SenderDocument>
</cm:Envelope>
XML;

        $body = [
            'EnvelopeXml' => $envelopeXml,
            'ConfirmationName' => 'CONF-1',
            'Recipients' => ['_PRIVATE@RECIPIENT_EXAMPLE'],
            'AttachmentsOutput' => [
                'AttachmentOutput' => [[
                    'ContentId' => 'file-1',
                    'IsSeparateCall' => false,
                    'SectionCount' => 1,
                    'SectionSize' => 6014,
                    'Contents' => base64_encode('<Invoice/>'),
                    'DecryptedContent' => '<Invoice/>',
                ]],
            ],
        ];

        $summary = DivMessageSummary::build($body);

        $this->assertIsArray($summary);
        $this->assertSame('SenderSection', $summary['sender_document_id'] ?? null);
        $this->assertSame('CONF-1', $summary['confirmation_name'] ?? null);
        $this->assertSame('Invoice INV-001', $summary['document']['title'] ?? null);
        $this->assertSame('EINVOICE', $summary['document']['kind']['code'] ?? null);
        $this->assertSame('_PRIVATE@SENDER_EXAMPLE', $summary['sender']['e_address'] ?? null);
        $this->assertTrue($summary['sender']['notify_on_delivery'] ?? false);

        $recipients = $summary['recipients'] ?? null;
        $this->assertIsArray($recipients);
        $this->assertSame('_PRIVATE@RECIPIENT_EXAMPLE', $recipients[0]['e_address'] ?? null);
        $this->assertSame('thumb-1', $recipients[0]['encryption']['certificate_thumbprint'] ?? null);
        $this->assertTrue($recipients[0]['encryption']['has_key'] ?? false);

        $attachments = $summary['attachments'] ?? null;
        $this->assertIsArray($attachments);
        $this->assertCount(1, $attachments);
        $this->assertSame('invoice.xml', $attachments[0]['name'] ?? null);
        $this->assertSame('application/xml', $attachments[0]['mime_type'] ?? null);
        $this->assertSame(6014, $attachments[0]['size'] ?? null);
        $this->assertFalse($attachments[0]['is_separate_call'] ?? true);
        $this->assertTrue($attachments[0]['has_contents'] ?? false);
        $this->assertSame(strlen('<Invoice/>'), $attachments[0]['contents_len'] ?? null);
        $this->assertSame(strlen('<Invoice/>'), $attachments[0]['decrypted_len'] ?? null);
    }

    public function test_build_falls_back_to_body_recipients_when_envelope_entries_are_missing(): void
    {
        $body = [
            'EnvelopeXml' => '<Envelope><SenderDocument Id="SenderSection" /></Envelope>',
            'Recipients' => ['_PRIVATE@fallback'],
        ];

        $summary = DivMessageSummary::build($body);

        $this->assertIsArray($summary);
        $this->assertSame('_PRIVATE@fallback', $summary['recipients'][0]['e_address'] ?? null);
    }
}
