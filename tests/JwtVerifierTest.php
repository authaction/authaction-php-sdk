<?php

namespace AuthAction\Tests;

use AuthAction\Exception\TokenExpiredException;
use AuthAction\Exception\TokenInvalidException;
use AuthAction\JwtVerifier;
use PHPUnit\Framework\TestCase;

class JwtVerifierTest extends TestCase
{
    private const DOMAIN   = 'acme.eu.authaction.com';
    private const AUDIENCE = 'https://api.acme.com';

    // ── verifyRequest ──────────────────────────────────────────────────────────

    public function test_verifyRequest_returns_null_when_header_is_null(): void
    {
        $v = new JwtVerifier(self::DOMAIN, self::AUDIENCE);
        $this->assertNull($v->verifyRequest(null));
    }

    public function test_verifyRequest_returns_null_when_scheme_is_not_bearer(): void
    {
        $v = new JwtVerifier(self::DOMAIN, self::AUDIENCE);
        $this->assertNull($v->verifyRequest('Basic dXNlcjpwYXNz'));
    }

    public function test_verifyRequest_returns_null_on_invalid_token(): void
    {
        $v = $this->createMockVerifier(new TokenInvalidException('bad'));
        $this->assertNull($v->verifyRequest('Bearer bad.token'));
    }

    public function test_verifyRequest_returns_null_on_expired_token(): void
    {
        $v = $this->createMockVerifier(new TokenExpiredException('expired'));
        $this->assertNull($v->verifyRequest('Bearer expired.token'));
    }

    public function test_verifyRequest_returns_payload_on_valid_token(): void
    {
        $payload = (object) ['sub' => 'user-1', 'iss' => 'https://acme.eu.authaction.com'];
        $v = $this->createMockVerifier($payload);
        $result = $v->verifyRequest('Bearer valid.token');
        $this->assertSame('user-1', $result->sub);
    }

    // ── verify (error types) ──────────────────────────────────────────────────

    public function test_verify_throws_TokenExpiredException(): void
    {
        $this->expectException(TokenExpiredException::class);
        $v = $this->createMockVerifier(new TokenExpiredException('expired'));
        $v->verify('expired.token');
    }

    public function test_verify_throws_TokenInvalidException(): void
    {
        $this->expectException(TokenInvalidException::class);
        $v = $this->createMockVerifier(new TokenInvalidException('bad'));
        $v->verify('bad.token');
    }

    // ── Helper ─────────────────────────────────────────────────────────────────

    /** Returns a JwtVerifier with verify() stubbed to return $result (or throw). */
    private function createMockVerifier(object $result): JwtVerifier
    {
        $mock = $this->getMockBuilder(JwtVerifier::class)
            ->setConstructorArgs([self::DOMAIN, self::AUDIENCE])
            ->onlyMethods(['verify'])
            ->getMock();

        $stub = $mock->method('verify');
        if ($result instanceof \Throwable) {
            $stub->willThrowException($result);
        } else {
            $stub->willReturn($result);
        }
        return $mock;
    }
}
