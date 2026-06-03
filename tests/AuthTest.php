<?php

declare(strict_types=1);

namespace AuthAction\Tests;

use AuthAction\Auth;
use AuthAction\Cookies;
use AuthAction\HttpClientInterface;
use AuthAction\Session;
use PHPUnit\Framework\TestCase;

class AuthTest extends TestCase
{
    private const SECRET = 'test-session-secret-at-least-32ch!';

    private function config(array $extra = []): array
    {
        return array_merge([
            'domain'        => 'app.eu.authaction.com',
            'clientId'      => 'test-client',
            'redirectUri'   => 'https://myapp.com/callback',
            'sessionSecret' => self::SECRET,
        ], $extra);
    }

    private function mockHttp(array $responses): HttpClientInterface
    {
        $http = $this->createMock(HttpClientInterface::class);
        $http->method('request')->willReturnCallback(
            function (string $method, string $url) use ($responses): array {
                foreach ($responses as $pattern => $response) {
                    if (str_contains($url, $pattern)) {
                        return $response;
                    }
                }
                return ['status' => 500, 'body' => '{}'];
            },
        );
        return $http;
    }

    // ── handleLogin ───────────────────────────────────────────────────────────────

    public function testHandleLoginReturnsAuthorizationUrl(): void
    {
        $result = (new Auth($this->config()))->handleLogin();
        self::assertStringContainsString('app.eu.authaction.com/oauth2/authorize', $result['url']);
    }

    public function testHandleLoginSetsPkceCookieWithShortMaxAge(): void
    {
        $result = (new Auth($this->config()))->handleLogin();
        self::assertStringContainsString('__aa_pkce=', $result['cookie']);
        self::assertStringContainsString('Max-Age=600', $result['cookie']);
    }

    public function testHandleLoginPkceCookieIsHttpOnly(): void
    {
        $result = (new Auth($this->config()))->handleLogin();
        self::assertStringContainsString('HttpOnly', $result['cookie']);
    }

    public function testHandleLoginPkceCookieContainsStateAndVerifier(): void
    {
        $result = (new Auth($this->config()))->handleLogin();
        preg_match('/__aa_pkce=([^;]+)/', $result['cookie'], $m);
        $pkce = json_decode(urldecode($m[1]), associative: true);
        self::assertArrayHasKey('state', $pkce);
        self::assertArrayHasKey('codeVerifier', $pkce);
    }

    // ── handleCallback — error paths ──────────────────────────────────────────────

    public function testHandleCallbackWithErrorParamReturnsErrorRedirect(): void
    {
        $result = (new Auth($this->config()))->handleCallback('error=access_denied', '');
        self::assertSame('/?error=access_denied', $result['redirect']);
        self::assertEmpty($result['cookies']);
    }

    public function testHandleCallbackMissingCodeReturnsErrorRedirect(): void
    {
        $result = (new Auth($this->config()))->handleCallback('state=xyz', '');
        self::assertSame('/?error=missing_code', $result['redirect']);
    }

    public function testHandleCallbackMissingPkceCookieReturnsErrorRedirect(): void
    {
        $result = (new Auth($this->config()))->handleCallback('code=abc&state=xyz', '');
        self::assertSame('/?error=missing_pkce', $result['redirect']);
    }

    public function testHandleCallbackStateMismatchReturnsErrorRedirect(): void
    {
        $pkce   = urlencode(json_encode(['state' => 'expected', 'codeVerifier' => 'cv']));
        $result = (new Auth($this->config()))->handleCallback(
            'code=abc&state=wrong',
            "__aa_pkce={$pkce}",
        );
        self::assertSame('/?error=state_mismatch', $result['redirect']);
    }

    // ── handleCallback — success path ─────────────────────────────────────────────

    public function testHandleCallbackSuccessRedirectsToLoginRedirect(): void
    {
        $http = $this->mockHttp([
            '/oauth2/token'   => ['status' => 200, 'body' => json_encode(['access_token' => 'at', 'refresh_token' => 'rt', 'expires_in' => 3600, 'token_type' => 'Bearer'])],
            '/oidc/userinfo'  => ['status' => 200, 'body' => json_encode(['sub' => 'u1', 'email' => 'u@test.com'])],
        ]);

        $pkce   = urlencode(json_encode(['state' => 'abc123', 'codeVerifier' => 'cv']));
        $result = (new Auth($this->config(), $http))->handleCallback(
            'code=valid-code&state=abc123',
            "__aa_pkce={$pkce}",
        );

        self::assertSame('/', $result['redirect']);
    }

    public function testHandleCallbackSuccessSetsSessionCookieAndClearsPkce(): void
    {
        $http = $this->mockHttp([
            '/oauth2/token'  => ['status' => 200, 'body' => json_encode(['access_token' => 'at', 'refresh_token' => 'rt', 'expires_in' => 3600, 'token_type' => 'Bearer'])],
            '/oidc/userinfo' => ['status' => 200, 'body' => json_encode(['sub' => 'u1'])],
        ]);

        $pkce   = urlencode(json_encode(['state' => 's', 'codeVerifier' => 'cv']));
        $result = (new Auth($this->config(), $http))->handleCallback(
            'code=c&state=s',
            "__aa_pkce={$pkce}",
        );

        self::assertCount(2, $result['cookies']);
        self::assertStringContainsString('__aa_session=', $result['cookies'][0]);
        self::assertStringContainsString('Max-Age=0', $result['cookies'][1]); // PKCE cookie cleared
    }

    public function testHandleCallbackCustomLoginRedirect(): void
    {
        $http = $this->mockHttp([
            '/oauth2/token'  => ['status' => 200, 'body' => json_encode(['access_token' => 'at', 'expires_in' => 3600, 'token_type' => 'Bearer'])],
            '/oidc/userinfo' => ['status' => 200, 'body' => json_encode(['sub' => 'u1'])],
        ]);

        $pkce   = urlencode(json_encode(['state' => 's', 'codeVerifier' => 'cv']));
        $result = (new Auth($this->config(['loginRedirect' => '/dashboard']), $http))->handleCallback(
            'code=c&state=s',
            "__aa_pkce={$pkce}",
        );

        self::assertSame('/dashboard', $result['redirect']);
    }

    // ── getSession ─────────────────────────────────────────────────────────────────

    public function testGetSessionReturnsNullWhenNoCookie(): void
    {
        self::assertNull((new Auth($this->config()))->getSession(''));
    }

    public function testGetSessionReturnsNullWhenSessionCookieMissing(): void
    {
        self::assertNull((new Auth($this->config()))->getSession('other=cookie'));
    }

    public function testGetSessionDecryptsValidSession(): void
    {
        $sessionData = ['user' => ['sub' => 'u1'], 'accessToken' => 'at', 'expiresAt' => PHP_INT_MAX];
        $encrypted   = Session::encrypt($sessionData, self::SECRET);
        $cookieHeader = Cookies::serialize('__aa_session', $encrypted);

        $session = (new Auth($this->config()))->getSession($cookieHeader);

        self::assertNotNull($session);
        self::assertSame('at', $session['accessToken']);
        self::assertSame('u1', $session['user']['sub']);
    }

    public function testGetSessionReturnsNullForExpiredSession(): void
    {
        $encrypted    = Session::encrypt(['user' => ['sub' => 'u1'], 'accessToken' => 'at'], self::SECRET, -1);
        $cookieHeader = Cookies::serialize('__aa_session', $encrypted);

        self::assertNull((new Auth($this->config()))->getSession($cookieHeader));
    }

    public function testGetSessionUsesCustomCookieName(): void
    {
        $encrypted    = Session::encrypt(['user' => ['sub' => 'u1'], 'accessToken' => 'at'], self::SECRET);
        $cookieHeader = Cookies::serialize('my_session', $encrypted);

        $auth = new Auth($this->config(['cookieName' => 'my_session']));

        self::assertNotNull($auth->getSession($cookieHeader));
    }

    // ── handleLogout ──────────────────────────────────────────────────────────────

    public function testHandleLogoutReturnsLogoutUrl(): void
    {
        $result = (new Auth($this->config()))->handleLogout('https://myapp.com/');
        self::assertStringContainsString('app.eu.authaction.com/oidc/logout', $result['url']);
    }

    public function testHandleLogoutClearsSessionCookieWithMaxAgeZero(): void
    {
        $result = (new Auth($this->config()))->handleLogout();
        self::assertStringContainsString('__aa_session=', $result['cookie']);
        self::assertStringContainsString('Max-Age=0', $result['cookie']);
    }

    // ── handleCallback — exception propagation ────────────────────────────────────

    public function testHandleCallbackPropagatesExchangeCodeException(): void
    {
        $http = $this->createMock(HttpClientInterface::class);
        $http->method('request')->willReturn([
            'status' => 400,
            'body'   => json_encode(['error' => 'invalid_grant', 'error_description' => 'Code expired']),
        ]);

        $pkce = urlencode(json_encode(['state' => 's', 'codeVerifier' => 'cv']));

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Code expired');
        (new Auth($this->config(), $http))->handleCallback('code=c&state=s', "__aa_pkce={$pkce}");
    }

    public function testHandleCallbackPropagatesGetUserInfoException(): void
    {
        $http = $this->mockHttp([
            '/oauth2/token'  => ['status' => 200, 'body' => json_encode(['access_token' => 'at', 'expires_in' => 3600, 'token_type' => 'Bearer'])],
            '/oidc/userinfo' => ['status' => 401, 'body' => ''],
        ]);

        $pkce = urlencode(json_encode(['state' => 's', 'codeVerifier' => 'cv']));

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('UserInfo failed: 401');
        (new Auth($this->config(), $http))->handleCallback('code=c&state=s', "__aa_pkce={$pkce}");
    }

    // ── handleCallback — session content ─────────────────────────────────────────

    public function testHandleCallbackSessionCookieContainsUserData(): void
    {
        $http = $this->mockHttp([
            '/oauth2/token'  => ['status' => 200, 'body' => json_encode(['access_token' => 'at-xyz', 'refresh_token' => 'rt', 'expires_in' => 3600, 'token_type' => 'Bearer'])],
            '/oidc/userinfo' => ['status' => 200, 'body' => json_encode(['sub' => 'user-42', 'email' => 'user@test.com'])],
        ]);

        $pkce   = urlencode(json_encode(['state' => 's', 'codeVerifier' => 'cv']));
        $result = (new Auth($this->config(), $http))->handleCallback('code=c&state=s', "__aa_pkce={$pkce}");

        // Extract the encrypted session value from the Set-Cookie header
        preg_match('/__aa_session=([^;]+)/', $result['cookies'][0], $m);
        $session = \AuthAction\Session::decrypt($m[1], self::SECRET);

        self::assertSame('user-42', $session['user']['sub']);
        self::assertSame('at-xyz', $session['accessToken']);
        self::assertSame('rt', $session['refreshToken']);
        self::assertArrayHasKey('expiresAt', $session);
    }
}
