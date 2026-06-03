<?php

declare(strict_types=1);

namespace AuthAction;

interface HttpClientInterface
{
    /**
     * @param  string[]         $headers  Header lines, e.g. ['Content-Type: application/json']
     * @return array{status: int, body: string}
     */
    public function request(string $method, string $url, array $headers = [], ?string $body = null): array;
}
