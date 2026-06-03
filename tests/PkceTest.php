<?php

declare(strict_types=1);

namespace AuthAction\Tests;

use AuthAction\Pkce;
use PHPUnit\Framework\TestCase;

class PkceTest extends TestCase
{
    public function testGenerateVerifierIsBase64Url(): void
    {
        $verifier = Pkce::generateVerifier();
        self::assertMatchesRegularExpression('/^[A-Za-z0-9\-_]+$/', $verifier);
    }

    public function testGenerateVerifierIs43Chars(): void
    {
        // 32 random bytes → 43 base64url chars (no padding)
        self::assertSame(43, strlen(Pkce::generateVerifier()));
    }

    public function testGenerateVerifierIsRandom(): void
    {
        self::assertNotSame(Pkce::generateVerifier(), Pkce::generateVerifier());
    }

    public function testGenerateChallengeIsS256HashOfVerifier(): void
    {
        $verifier  = Pkce::generateVerifier();
        $challenge = Pkce::generateChallenge($verifier);
        $expected  = rtrim(strtr(base64_encode(hash('sha256', $verifier, binary: true)), '+/', '-_'), '=');

        self::assertSame($expected, $challenge);
    }

    public function testGenerateChallengeIsBase64Url(): void
    {
        $challenge = Pkce::generateChallenge('some-verifier-string');
        self::assertMatchesRegularExpression('/^[A-Za-z0-9\-_]+$/', $challenge);
    }

    public function testGenerateChallengeIsDeterministicForSameVerifier(): void
    {
        $verifier = Pkce::generateVerifier();
        self::assertSame(Pkce::generateChallenge($verifier), Pkce::generateChallenge($verifier));
    }

    public function testGenerateStateIs32HexChars(): void
    {
        $state = Pkce::generateState();
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $state);
    }

    public function testGenerateStateIsRandom(): void
    {
        self::assertNotSame(Pkce::generateState(), Pkce::generateState());
    }
}
