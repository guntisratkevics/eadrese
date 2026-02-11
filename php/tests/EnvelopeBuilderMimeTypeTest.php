<?php

declare(strict_types=1);

use LatvianEinvoice\Attachment;
use LatvianEinvoice\Envelope\Builder;
use PHPUnit\Framework\TestCase;

final class EnvelopeBuilderMimeTypeTest extends TestCase
{
    public function test_encrypted_text_mime_is_normalized(): void
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
        $this->assertSame('application/octet-stream', $file['MimeType']);
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
}
