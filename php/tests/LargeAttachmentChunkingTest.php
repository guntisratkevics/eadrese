<?php

declare(strict_types=1);

use LatvianEinvoice\Soap\DirectSoapClient;
use PHPUnit\Framework\TestCase;

final class LargeAttachmentChunkingTest extends TestCase
{
    public function test_split_inline_and_separate_prefers_smallest_payloads_within_4mb_budget(): void
    {
        $items = [
            ['index' => 0, 'content_id' => '0', 'contents_b64' => 'A', 'contents_bytes' => 'A', 'size' => 3 * 1024 * 1024],
            ['index' => 1, 'content_id' => '1', 'contents_b64' => 'B', 'contents_bytes' => 'B', 'size' => 2 * 1024 * 1024],
            ['index' => 2, 'content_id' => '2', 'contents_b64' => 'C', 'contents_bytes' => 'C', 'size' => 1 * 1024 * 1024],
        ];

        $method = new ReflectionMethod(DirectSoapClient::class, 'splitInlineAndSeparateAttachmentItems');
        $method->setAccessible(true);

        [$inline, $separate] = $method->invoke(null, $items);
        $this->assertSame([1, 2], array_values(array_map(static fn(array $item): int => $item['index'], $inline)));
        $this->assertSame([0], array_values(array_map(static fn(array $item): int => $item['index'], $separate)));
    }

    public function test_build_attachment_sections_adds_terminal_empty_section_for_exact_4mb_multiple(): void
    {
        $contents = str_repeat('A', 4 * 1024 * 1024);

        $method = new ReflectionMethod(DirectSoapClient::class, 'buildAttachmentSections');
        $method->setAccessible(true);
        $sections = $method->invoke(null, $contents);

        $this->assertCount(2, $sections);
        $this->assertSame(4 * 1024 * 1024, strlen((string)$sections[0]));
        $this->assertNull($sections[1]);
    }

    public function test_build_attachment_sections_without_exact_multiple_has_no_terminal_empty_section(): void
    {
        $contents = str_repeat('B', (4 * 1024 * 1024) + 1);

        $method = new ReflectionMethod(DirectSoapClient::class, 'buildAttachmentSections');
        $method->setAccessible(true);
        $sections = $method->invoke(null, $contents);

        $this->assertCount(2, $sections);
        $this->assertSame(4 * 1024 * 1024, strlen((string)$sections[0]));
        $this->assertSame(1, strlen((string)$sections[1]));
    }

    public function test_parse_attachment_input_items_requires_contents_field(): void
    {
        $method = new ReflectionMethod(DirectSoapClient::class, 'parseAttachmentInputItems');
        $method->setAccessible(true);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('AttachmentInput without Contents');

        $method->invoke(null, [
            'AttachmentInput' => [
                ['ContentId' => '0'],
            ],
        ]);
    }
}

