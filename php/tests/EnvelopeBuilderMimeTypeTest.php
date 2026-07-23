<?php

declare(strict_types=1);

use LatvianEinvoice\Attachment;
use LatvianEinvoice\Envelope\Builder;
use PHPUnit\Framework\TestCase;

final class EnvelopeBuilderMimeTypeTest extends TestCase
{
    public function test_encrypted_attachment_keeps_logical_file_metadata(): void
    {
        $attachment = new Attachment('a.txt', 'ABC', 'text/plain');

        [$envelope] = Builder::buildEnvelope(
            senderEAddress: '_DEFAULT@90000000000',
            recipients: ['0101'],
            documentKindCode: 'DOC_EMPTY',
            subject: 'Test',
            bodyText: 'Body',
            attachments: [$attachment],
            symmetricKeyBytes: str_repeat("\x01", 32)
        );

        $file = $envelope['SenderDocument']['DocumentMetadata']['PayloadReference']['File'][0];
        $this->assertSame('text/plain', $file['MimeType']);
        $this->assertSame(3, $file['Size']);
        $this->assertSame(
            base64_encode(hash('sha512', 'ABC', true)),
            $file['Content']['DigestValue']
        );
    }

    public function test_plain_text_mime_is_kept_when_not_encrypted(): void
    {
        $attachment = new Attachment('a.txt', 'ABC', 'text/plain');

        [$envelope] = Builder::buildEnvelope(
            senderEAddress: '_DEFAULT@90000000000',
            recipients: ['0101'],
            documentKindCode: 'DOC_EMPTY',
            subject: 'Test',
            bodyText: 'Body',
            attachments: [$attachment]
        );

        $file = $envelope['SenderDocument']['DocumentMetadata']['PayloadReference']['File'][0];
        $this->assertSame('text/plain', $file['MimeType']);
    }

    public function test_reply_reference_is_added_to_common_metadata(): void
    {
        [$envelope] = Builder::buildEnvelope(
            senderEAddress: '_DEFAULT@40000000000',
            recipients: ['_DEFAULT@40000000001'],
            documentKindCode: 'DOC_EMPTY',
            subject: 'Re: Test',
            bodyText: 'Reply body',
            referenceId: 'ORIGINAL-MESSAGE-ID-001'
        );

        $references = $envelope['SenderDocument']['DocumentMetadata']
            ['CommonMetadata']['DocumentReferences']['ReferenceEntry'];

        $this->assertSame(
            [['RefRegistrationNumber' => 'ORIGINAL-MESSAGE-ID-001']],
            $references
        );
    }

}
