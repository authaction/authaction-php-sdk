<?php

declare(strict_types=1);

namespace AuthAction;

final class Pkce
{
    public static function generateVerifier(): string
    {
        return self::b64u(random_bytes(32));
    }

    public static function generateChallenge(string $verifier): string
    {
        return self::b64u(hash('sha256', $verifier, binary: true));
    }

    public static function generateState(): string
    {
        return bin2hex(random_bytes(16));
    }

    private static function b64u(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
