<?php

declare(strict_types=1);

namespace AuthAction\Tests;

use AuthAction\AuthAction;
use AuthAction\AuthActionClient;
use AuthAction\Auth;
use PHPUnit\Framework\TestCase;

class AuthActionTest extends TestCase
{
    private const BASE_CONFIG = [
        'domain'        => 'myapp.eu.authaction.com',
        'clientId'      => 'client-id-123',
        'redirectUri'   => 'https://myapp.com/callback',
        'sessionSecret' => 'a-secret-that-is-long-enough-for-test',
    ];

    // ── factory methods ───────────────────────────────────────────────────────────

    public function testCreateClientReturnsAuthActionClient(): void
    {
        self::assertInstanceOf(AuthActionClient::class, AuthAction::createClient(self::BASE_CONFIG));
    }

    public function testCreateAuthReturnsAuth(): void
    {
        self::assertInstanceOf(Auth::class, AuthAction::createAuth(self::BASE_CONFIG));
    }

    // ── verifyFromHeader ─────────────────────────────────────────────────────────

    public function testVerifyFromHeaderReturnsNullForNull(): void
    {
        $aa = new AuthAction('myapp.eu.authaction.com', 'https://api.myapp.com');
        self::assertNull($aa->verifyFromHeader(null));
    }

    public function testVerifyFromHeaderReturnsNullForEmptyString(): void
    {
        $aa = new AuthAction('myapp.eu.authaction.com', 'https://api.myapp.com');
        self::assertNull($aa->verifyFromHeader(''));
    }

    public function testVerifyFromHeaderReturnsNullForNonBearerScheme(): void
    {
        $aa = new AuthAction('myapp.eu.authaction.com', 'https://api.myapp.com');
        self::assertNull($aa->verifyFromHeader('Basic dXNlcjpwYXNz'));
    }

    public function testVerifyFromHeaderReturnsNullForMalformedToken(): void
    {
        $aa = new AuthAction('myapp.eu.authaction.com', 'https://api.myapp.com');
        // verifyFromHeader must never throw — it swallows errors and returns null
        self::assertNull($aa->verifyFromHeader('Bearer not.a.real.jwt'));
    }
}
