<?php

declare(strict_types=1);

namespace AuthAction;

final class AuthorizationUrlResult
{
    public function __construct(
        public readonly string $url,
        public readonly string $state,
        public readonly string $codeVerifier,
    ) {}
}
