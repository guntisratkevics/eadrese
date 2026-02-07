<?php

declare(strict_types=1);

namespace LatvianEinvoice;

final class Attachment
{
    public string $filename;
    public string $content;
    public string $contentType;

    public function __construct(string $filename, string $content, string $contentType = 'application/octet-stream')
    {
        $this->filename = $filename;
        $this->content = $content;
        $this->contentType = $contentType;
    }

    public function sha512Digest(): string
    {
        return hash('sha512', $this->content, true);
    }
}
