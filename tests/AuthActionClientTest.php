<?php

declare(strict_types=1);

namespace AuthAction\Tests;

use AuthAction\AuthActionClient;
use AuthAction\AuthorizationUrlResult;
use AuthAction\HttpClientInterface;
use PHPUnit\Framework\TestCase;

class AuthActionClientTest extends TestCase
{
    private const CONFIG = [
        'domain'      => 'myapp.eu.authaction.com',
        'clientId'    => 'client-id-123',
        'redirectUri' => 'https://myapp.com/callback',
        'scope'       => 'openid profile email',
    ];

    private function makeClient(?HttpClientInterface $http = null): AuthActionClient
    {
        return new AuthActionClient(self::CONFIG, $http);
    }

    // ── getAuthorizationUrl ──────────────────────────────────────────────────────

    public function testGetAuthorizationUrlReturnsResult(): void
    {
        self::assertInstanceOf(AuthorizationUrlResult::class, $this->makeClient()->getAuthorizationUrl());
    }

    public function testGetAuthorizationUrlUrlContainsDomainAndPath(): void
    {
        $result = $this->makeClient()->getAuthorizationUrl();
        self::assertStringContainsString('myapp.eu.authaction.com/oauth2/authorize', $result->url);
    }

    public function testGetAuthorizationUrlContainsPkceParams(): void
    {
        $result = $this->makeClient()->getAuthorizationUrl();
        self::assertStringContainsString('code_challenge=', $result->url);
        self::assertStringContainsString('code_challenge_method=S256', $result->url);
    }

    public function testGetAuthorizationUrlContainsClientIdAndRedirectUri(): void
    {
        $result = $this->makeClient()->getAuthorizationUrl();
        self::assertStringContainsString('client_id=client-id-123', $result->url);
        self::assertStringContainsString('redirect_uri=', $result->url);
    }

    public function testGetAuthorizationUrlReturnsNonEmptyStateAndVerifier(): void
    {
        $result = $this->makeClient()->getAuthorizationUrl();
        self::assertNotEmpty($result->state);
        self::assertNotEmpty($result->codeVerifier);
    }

    public function testGetAuthorizationUrlStateMatchesUrlParam(): void
    {
        $result = $this->makeClient()->getAuthorizationUrl();
        self::assertStringContainsString("state={$result->state}", $result->url);
    }

    public function testGetAuthorizationUrlAcceptsCustomState(): void
    {
        $result = $this->makeClient()->getAuthorizationUrl(['state' => 'my-custom-state']);
        self::assertStringContainsString('state=my-custom-state', $result->url);
        self::assertSame('my-custom-state', $result->state);
    }

    public function testGetAuthorizationUrlMergesExtraAuthorizationParams(): void
    {
        $result = $this->makeClient()->getAuthorizationUrl([
            'authorizationParams' => ['prompt' => 'login'],
        ]);
        self::assertStringContainsString('prompt=login', $result->url);
    }

    public function testGetAuthorizationUrlMergesConfigLevelAuthorizationParams(): void
    {
        $client = new AuthActionClient(array_merge(self::CONFIG, [
            'authorizationParams' => ['audience' => 'https://api.myapp.com'],
        ]));
        self::assertStringContainsString('audience=', $client->getAuthorizationUrl()->url);
    }

    public function testGetAuthorizationUrlIsNondeterministic(): void
    {
        $client = $this->makeClient();
        self::assertNotSame(
            $client->getAuthorizationUrl()->codeVerifier,
            $client->getAuthorizationUrl()->codeVerifier,
        );
    }

    public function testGetAuthorizationUrlUsesDefaultScopeWhenNotConfigured(): void
    {
        $client = new AuthActionClient([
            'domain'      => 'myapp.eu.authaction.com',
            'clientId'    => 'client-id-123',
            'redirectUri' => 'https://myapp.com/callback',
            // scope intentionally omitted
        ]);
        self::assertStringContainsString('scope=openid+profile+email', $client->getAuthorizationUrl()->url);
    }

    public function testGetAuthorizationUrlUsesConfiguredScope(): void
    {
        $client = new AuthActionClient(array_merge(self::CONFIG, ['scope' => 'openid offline_access']));
        self::assertStringContainsString('scope=openid+offline_access', $client->getAuthorizationUrl()->url);
    }

    // ── getLogoutUrl ─────────────────────────────────────────────────────────────

    public function testGetLogoutUrlContainsDomainAndClientId(): void
    {
        $url = $this->makeClient()->getLogoutUrl();
        self::assertStringContainsString('myapp.eu.authaction.com/oidc/logout', $url);
        self::assertStringContainsString('client_id=client-id-123', $url);
    }

    public function testGetLogoutUrlWithReturnToIncludesRedirectParam(): void
    {
        $url = $this->makeClient()->getLogoutUrl('https://myapp.com/');
        self::assertStringContainsString('post_logout_redirect_uri=', $url);
    }

    public function testGetLogoutUrlWithoutReturnToOmitsRedirectParam(): void
    {
        $url = $this->makeClient()->getLogoutUrl();
        self::assertStringNotContainsString('post_logout_redirect_uri', $url);
    }

    public function testGetLogoutUrlUsesConfigPostLogoutRedirectUri(): void
    {
        $client = new AuthActionClient(array_merge(self::CONFIG, [
            'postLogoutRedirectUri' => 'https://myapp.com/bye',
        ]));
        self::assertStringContainsString('post_logout_redirect_uri=', $client->getLogoutUrl());
    }

    // ── exchangeCode ─────────────────────────────────────────────────────────────

    public function testExchangeCodeCallsTokenEndpointAndReturnsTokens(): void
    {
        $http = $this->createMock(HttpClientInterface::class);
        $http->expects(self::once())
            ->method('request')
            ->with('POST', 'https://myapp.eu.authaction.com/oauth2/token')
            ->willReturn([
                'status' => 200,
                'body'   => json_encode([
                    'access_token'  => 'at-abc',
                    'refresh_token' => 'rt-xyz',
                    'expires_in'    => 3600,
                    'token_type'    => 'Bearer',
                ]),
            ]);

        $tokens = $this->makeClient($http)->exchangeCode('code123', 'verifier123');

        self::assertSame('at-abc', $tokens['access_token']);
        self::assertSame('rt-xyz', $tokens['refresh_token']);
    }

    public function testExchangeCodeThrowsOnErrorResponse(): void
    {
        $http = $this->createMock(HttpClientInterface::class);
        $http->method('request')->willReturn([
            'status' => 400,
            'body'   => json_encode(['error' => 'invalid_grant', 'error_description' => 'Code expired']),
        ]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Code expired');
        $this->makeClient($http)->exchangeCode('bad', 'bad');
    }

    public function testExchangeCodeFallsBackToErrorKeyWhenNoDescription(): void
    {
        $http = $this->createMock(HttpClientInterface::class);
        $http->method('request')->willReturn([
            'status' => 400,
            'body'   => json_encode(['error' => 'invalid_request']),
        ]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid_request');
        $this->makeClient($http)->exchangeCode('bad', 'bad');
    }

    public function testExchangeCodeIncludesClientSecretWhenConfigured(): void
    {
        $http = $this->createMock(HttpClientInterface::class);
        $http->expects(self::once())
            ->method('request')
            ->with(
                'POST',
                self::anything(),
                self::anything(),
                self::stringContains('client_secret=s3cr3t'),
            )
            ->willReturn(['status' => 200, 'body' => json_encode(['access_token' => 'at', 'expires_in' => 3600, 'token_type' => 'Bearer'])]);

        $client = new AuthActionClient(array_merge(self::CONFIG, ['clientSecret' => 's3cr3t']), $http);
        $client->exchangeCode('c', 'v');
    }

    // ── refreshTokens ─────────────────────────────────────────────────────────────

    public function testRefreshTokensCallsTokenEndpointAndReturnsNewTokens(): void
    {
        $http = $this->createMock(HttpClientInterface::class);
        $http->expects(self::once())
            ->method('request')
            ->with('POST', 'https://myapp.eu.authaction.com/oauth2/token')
            ->willReturn([
                'status' => 200,
                'body'   => json_encode(['access_token' => 'new-at', 'expires_in' => 3600, 'token_type' => 'Bearer']),
            ]);

        $tokens = $this->makeClient($http)->refreshTokens('rt123');
        self::assertSame('new-at', $tokens['access_token']);
    }

    // ── getUserInfo ───────────────────────────────────────────────────────────────

    public function testGetUserInfoCallsUserinfoEndpointAndReturnsUser(): void
    {
        $http = $this->createMock(HttpClientInterface::class);
        $http->expects(self::once())
            ->method('request')
            ->with('GET', 'https://myapp.eu.authaction.com/oidc/userinfo')
            ->willReturn([
                'status' => 200,
                'body'   => json_encode(['sub' => 'u123', 'email' => 'test@example.com']),
            ]);

        $user = $this->makeClient($http)->getUserInfo('access-token');
        self::assertSame('u123', $user['sub']);
        self::assertSame('test@example.com', $user['email']);
    }

    public function testGetUserInfoThrowsOnUnauthorized(): void
    {
        $http = $this->createMock(HttpClientInterface::class);
        $http->method('request')->willReturn(['status' => 401, 'body' => '']);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('UserInfo failed: 401');
        $this->makeClient($http)->getUserInfo('bad-token');
    }
}
