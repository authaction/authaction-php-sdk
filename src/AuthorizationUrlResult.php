<?php

declare(strict_types=1);

namespace AuthAction;

final readonly class AuthorizationUrlResult
{
    public function __construct(
        public string $url,
        public string $state,
        public string $codeVerifier,
    ) {}
}
