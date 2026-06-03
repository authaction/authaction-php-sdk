<?php

declare(strict_types=1);

namespace AuthAction\Tests;

use AuthAction\Session;
use PHPUnit\Framework\TestCase;

class SessionTest extends TestCase
{
    private const SECRET = 'super-secret-session-key-for-tests';

    public function testEncryptThenDecryptRoundtrip(): void
    {
        $data = [
            'user'        => ['sub' => 'u123', 'email' => 'test@example.com'],
            'accessToken' => 'tok-abc',
        ];
        $token  = Session::encrypt($data, self::SECRET);
        $result = Session::decrypt($token, self::SECRET);

        self::assertNotNull($result);
        self::assertSame('tok-abc', $result['accessToken']);
        self::assertSame('u123', $result['user']['sub']);
    }

    public function testDecryptWithWrongSecretReturnsNull(): void
    {
        $token = Session::encrypt(['foo' => 'bar'], self::SECRET);
        self::assertNull(Session::decrypt($token, 'wrong-secret'));
    }

    public function testDecryptExpiredSessionReturnsNull(): void
    {
        // maxAge of -1 sets exp in the past
        $token = Session::encrypt(['foo' => 'bar'], self::SECRET, -1);
        self::assertNull(Session::decrypt($token, self::SECRET));
    }

    public function testDecryptInvalidTokenFormatsReturnNull(): void
    {
        self::assertNull(Session::decrypt('not.valid.token', self::SECRET));
        self::assertNull(Session::decrypt('', self::SECRET));
        self::assertNull(Session::decrypt('onlyone', self::SECRET));
        self::assertNull(Session::decrypt('a.b', self::SECRET));
        self::assertNull(Session::decrypt('a.b.c.d', self::SECRET));
    }

    public function testDecryptTamperedCiphertextReturnsNull(): void
    {
        $token  = Session::encrypt(['foo' => 'bar'], self::SECRET);
        $parts  = explode('.', $token);
        $parts[1] = strrev($parts[1]); // corrupt ciphertext
        self::assertNull(Session::decrypt(implode('.', $parts), self::SECRET));
    }

    public function testDecryptTamperedTagReturnsNull(): void
    {
        $token  = Session::encrypt(['foo' => 'bar'], self::SECRET);
        $parts  = explode('.', $token);
        $parts[2] = strrev($parts[2]); // corrupt auth tag
        self::assertNull(Session::decrypt(implode('.', $parts), self::SECRET));
    }

    public function testEncryptProducesThreeBase64UrlSegments(): void
    {
        $token = Session::encrypt(['x' => 1], self::SECRET);
        $parts = explode('.', $token);
        self::assertCount(3, $parts);
        foreach ($parts as $part) {
            self::assertMatchesRegularExpression('/^[A-Za-z0-9\-_]+$/', $part);
        }
    }

    public function testEncryptIsNondeterministic(): void
    {
        $data = ['x' => 1];
        self::assertNotSame(
            Session::encrypt($data, self::SECRET),
            Session::encrypt($data, self::SECRET),
        );
    }

    public function testDecryptPreservesAllDataTypes(): void
    {
        $data = [
            'int'   => 42,
            'float' => 3.14,
            'bool'  => true,
            'null'  => null,
            'arr'   => [1, 2, 3],
            'map'   => ['key' => 'val'],
        ];
        $result = Session::decrypt(Session::encrypt($data, self::SECRET), self::SECRET);

        self::assertSame(42, $result['int']);
        self::assertSame(3.14, $result['float']);
        self::assertTrue($result['bool']);
        self::assertNull($result['null']);
        self::assertSame([1, 2, 3], $result['arr']);
        self::assertSame(['key' => 'val'], $result['map']);
    }

    public function testEncryptAddsIatAndExp(): void
    {
        $before = time();
        $result = Session::decrypt(Session::encrypt([], self::SECRET, 3600), self::SECRET);
        $after  = time();

        self::assertArrayHasKey('iat', $result);
        self::assertArrayHasKey('exp', $result);
        self::assertGreaterThanOrEqual($before, $result['iat']);
        self::assertLessThanOrEqual($after, $result['iat']);
        self::assertEqualsWithDelta($result['iat'] + 3600, $result['exp'], 1);
    }
}
