<?php

declare(strict_types=1);

namespace AuthAction;

class AuthActionClient
{
    private const DEFAULT_SCOPE = 'openid profile email';

    private HttpClientInterface $http;

    public function __construct(
        private readonly array $config,
        ?HttpClientInterface $httpClient = null,
    ) {
        $this->http = $httpClient ?? new CurlHttpClient();
    }

    public function getAuthorizationUrl(array $options = []): AuthorizationUrlResult
    {
        $state         = $options['state'] ?? Pkce::generateState();
        $codeVerifier  = Pkce::generateVerifier();
        $codeChallenge = Pkce::generateChallenge($codeVerifier);

        $params = array_merge([
            'response_type'         => 'code',
            'client_id'             => $this->config['clientId'],
            'redirect_uri'          => $this->config['redirectUri'],
            'scope'                 => $this->config['scope'] ?? self::DEFAULT_SCOPE,
            'state'                 => $state,
            'code_challenge'        => $codeChallenge,
            'code_challenge_method' => 'S256',
        ], $this->config['authorizationParams'] ?? [], $options['authorizationParams'] ?? []);

        return new AuthorizationUrlResult(
            url: "https://{$this->config['domain']}/oauth2/authorize?" . http_build_query($params),
            state: $state,
            codeVerifier: $codeVerifier,
        );
    }

    /** Exchange an authorization code for tokens. */
    public function exchangeCode(string $code, string $codeVerifier): array
    {
        $body = [
            'grant_type'    => 'authorization_code',
            'client_id'     => $this->config['clientId'],
            'code'          => $code,
            'redirect_uri'  => $this->config['redirectUri'],
            'code_verifier' => $codeVerifier,
        ];
        if (isset($this->config['clientSecret'])) {
            $body['client_secret'] = $this->config['clientSecret'];
        }
        return $this->tokenRequest($body);
    }

    /** Use a refresh token to obtain a new token set. */
    public function refreshTokens(string $refreshToken): array
    {
        $body = [
            'grant_type'    => 'refresh_token',
            'client_id'     => $this->config['clientId'],
            'refresh_token' => $refreshToken,
        ];
        if (isset($this->config['clientSecret'])) {
            $body['client_secret'] = $this->config['clientSecret'];
        }
        return $this->tokenRequest($body);
    }

    /** Fetch user info from the OIDC /userinfo endpoint. */
    public function getUserInfo(string $accessToken): array
    {
        $res = $this->http->request(
            'GET',
            "https://{$this->config['domain']}/oidc/userinfo",
            ["Authorization: Bearer {$accessToken}"],
        );
        if ($res['status'] < 200 || $res['status'] >= 300) {
            throw new \RuntimeException("UserInfo failed: {$res['status']}");
        }
        return json_decode($res['body'], associative: true, flags: JSON_THROW_ON_ERROR);
    }

    /** Build the OIDC logout URL. */
    public function getLogoutUrl(?string $returnTo = null): string
    {
        $logoutRedirect = $returnTo ?? $this->config['postLogoutRedirectUri'] ?? null;
        $params = ['client_id' => $this->config['clientId']];
        if ($logoutRedirect !== null) {
            $params['post_logout_redirect_uri'] = $logoutRedirect;
        }
        return "https://{$this->config['domain']}/oidc/logout?" . http_build_query($params);
    }

    private function tokenRequest(array $body): array
    {
        $res = $this->http->request(
            'POST',
            "https://{$this->config['domain']}/oauth2/token",
            ['Content-Type: application/x-www-form-urlencoded'],
            http_build_query($body),
        );
        $data = json_decode($res['body'], associative: true, flags: JSON_THROW_ON_ERROR);
        if ($res['status'] < 200 || $res['status'] >= 300) {
            throw new \RuntimeException(
                $data['error_description'] ?? $data['error'] ?? 'Token request failed',
            );
        }
        return $data;
    }
}
