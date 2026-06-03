<?php

declare(strict_types=1);

namespace AuthAction\Tests;

use AuthAction\Cookies;
use PHPUnit\Framework\TestCase;

class CookiesTest extends TestCase
{
    // ── parse ────────────────────────────────────────────────────────────────────

    public function testParseTypicalHeader(): void
    {
        $result = Cookies::parse('__aa_session=abc123; other=xyz');
        self::assertSame('abc123', $result['__aa_session']);
        self::assertSame('xyz', $result['other']);
    }

    public function testParseSingleCookie(): void
    {
        self::assertSame(['name' => 'value'], Cookies::parse('name=value'));
    }

    public function testParseEmptyHeaderReturnsEmptyArray(): void
    {
        self::assertSame([], Cookies::parse(''));
    }

    public function testParseCookieValueWithEqualsSign(): void
    {
        // Base64 values contain '=' which should not be split
        $result = Cookies::parse('token=aGVsbG8=');
        self::assertSame('aGVsbG8=', $result['token']);
    }

    public function testParseHandlesLeadingAndTrailingSpaces(): void
    {
        $result = Cookies::parse(' name = value ');
        self::assertSame('value', $result['name']);
    }

    // ── serialize ────────────────────────────────────────────────────────────────

    public function testSerializeBasicCookie(): void
    {
        self::assertSame('name=value', Cookies::serialize('name', 'value'));
    }

    public function testSerializeWithAllOptions(): void
    {
        $cookie = Cookies::serialize('__aa_session', 'tok', [
            'maxAge'   => 3600,
            'path'     => '/',
            'httpOnly' => true,
            'sameSite' => 'lax',
            'secure'   => true,
        ]);

        self::assertSame('__aa_session=tok; Max-Age=3600; Path=/; HttpOnly; SameSite=Lax; Secure', $cookie);
    }

    public function testSerializeMaxAgeZeroClearsCookie(): void
    {
        $cookie = Cookies::serialize('session', '', ['maxAge' => 0]);
        self::assertStringContainsString('Max-Age=0', $cookie);
    }

    public function testSerializeSameSiteIsCamelCased(): void
    {
        self::assertStringContainsString('SameSite=Strict', Cookies::serialize('x', 'y', ['sameSite' => 'strict']));
        self::assertStringContainsString('SameSite=Lax', Cookies::serialize('x', 'y', ['sameSite' => 'lax']));
        self::assertStringContainsString('SameSite=None', Cookies::serialize('x', 'y', ['sameSite' => 'none']));
    }

    public function testSerializeOmitsSecureWhenFalse(): void
    {
        $cookie = Cookies::serialize('x', 'y', ['secure' => false]);
        self::assertStringNotContainsString('Secure', $cookie);
    }

    public function testSerializeOmitsHttpOnlyWhenFalse(): void
    {
        $cookie = Cookies::serialize('x', 'y', ['httpOnly' => false]);
        self::assertStringNotContainsString('HttpOnly', $cookie);
    }

    public function testSerializeWithEmptyValueAndZeroMaxAge(): void
    {
        $cookie = Cookies::serialize('__aa_pkce', '', ['maxAge' => 0, 'path' => '/', 'httpOnly' => true]);
        self::assertStringStartsWith('__aa_pkce=; Max-Age=0', $cookie);
    }
}
