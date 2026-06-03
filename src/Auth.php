<?php

declare(strict_types=1);

namespace AuthAction;

/**
 * High-level session-based auth handler for framework-agnostic PHP backends.
 *
 * Manages the full login → callback → logout flow with encrypted session cookies.
 *
 * @example
 * ```php
 * $auth = new Auth([
 *     'domain'        => $_ENV['AUTHACTION_DOMAIN'],
 *     'clientId'      => $_ENV['AUTHACTION_CLIENT_ID'],
 *     'clientSecret'  => $_ENV['AUTHACTION_CLIENT_SECRET'],
 *     'redirectUri'   => $_ENV['AUTHACTION_REDIRECT_URI'],
 *     'sessionSecret' => $_ENV['SESSION_SECRET'],
 * ]);
 *
 * // Login route
 * ['url' => $url, 'cookie' => $cookie] = $auth->handleLogin();
 * header("Set-Cookie: {$cookie}");
 * header("Location: {$url}"); exit;
 *
 * // Callback route
 * ['redirect' => $redirect, 'cookies' => $cookies] = $auth->handleCallback(
 *     $_SERVER['QUERY_STRING'],
 *     $_SERVER['HTTP_COOKIE'] ?? '',
 * );
 * foreach ($cookies as $c) { header("Set-Cookie: {$c}", replace: false); }
 * header("Location: {$redirect}"); exit;
 *
 * // Protected route
 * $session = $auth->getSession($_SERVER['HTTP_COOKIE'] ?? '');
 * if ($session === null) { header('Location: /login'); exit; }
 * $user = $session['user'];
 * ```
 */
class Auth
{
    private const PKCE_COOKIE    = '__aa_pkce';
    private const DEFAULT_COOKIE = '__aa_session';
    private const DEFAULT_MAX_AGE = 604800; // 7 days

    private AuthActionClient $client;
    private string $cookieName;
    private int $maxAge;
    private string $loginRedirect;
    private bool $secure;

    public function __construct(
        private readonly array $config,
        ?HttpClientInterface $httpClient = null,
    ) {
        $this->client        = new AuthActionClient($config, $httpClient);
        $this->cookieName    = $config['cookieName'] ?? self::DEFAULT_COOKIE;
        $this->maxAge        = $config['cookieMaxAge'] ?? self::DEFAULT_MAX_AGE;
        $this->loginRedirect = $config['loginRedirect'] ?? '/';
        $this->secure        = $config['secure'] ?? (($_SERVER['HTTPS'] ?? '') !== '');
    }

    /**
     * Start the login flow.
     *
     * @return array{url: string, cookie: string}
     *   Redirect the user to `url` and set the `cookie` as a Set-Cookie header.
     */
    public function handleLogin(): array
    {
        $result = $this->client->getAuthorizationUrl();
        $pkce   = json_encode(['state' => $result->state, 'codeVerifier' => $result->codeVerifier]);

        return [
            'url'    => $result->url,
            'cookie' => Cookies::serialize(self::PKCE_COOKIE, urlencode($pkce), $this->cookieOpts(600)),
        ];
    }

    /**
     * Handle the OAuth2 callback.
     *
     * @param  string $queryString   The raw query string from the callback request (e.g. $_SERVER['QUERY_STRING'])
     * @param  string $cookieHeader  The raw Cookie header value (e.g. $_SERVER['HTTP_COOKIE'] ?? '')
     * @return array{redirect: string, cookies: string[]}
     *   Redirect to `redirect` and apply all `cookies` as Set-Cookie headers.
     */
    public function handleCallback(string $queryString, string $cookieHeader): array
    {
        $params = [];
        parse_str($queryString, $params);

        if (!empty($params['error'])) {
            return $this->errorRedirect($params['error']);
        }
        if (empty($params['code'])) {
            return $this->errorRedirect('missing_code');
        }

        $cookies = Cookies::parse($cookieHeader);
        $rawPkce = $cookies[self::PKCE_COOKIE] ?? null;
        if ($rawPkce === null) {
            return $this->errorRedirect('missing_pkce');
        }

        $pkce = json_decode(urldecode($rawPkce), associative: true);
        if (($params['state'] ?? '') !== ($pkce['state'] ?? '')) {
            return $this->errorRedirect('state_mismatch');
        }

        $tokens = $this->client->exchangeCode($params['code'], $pkce['codeVerifier']);
        $user   = $this->client->getUserInfo($tokens['access_token']);

        $sessionData = [
            'user'         => $user,
            'accessToken'  => $tokens['access_token'],
            'refreshToken' => $tokens['refresh_token'] ?? null,
            'expiresAt'    => (int) round(microtime(true) * 1000) + $tokens['expires_in'] * 1000,
        ];

        $encrypted = Session::encrypt($sessionData, $this->config['sessionSecret'], $this->maxAge);

        return [
            'redirect' => $this->loginRedirect,
            'cookies'  => [
                Cookies::serialize($this->cookieName, $encrypted, $this->cookieOpts($this->maxAge)),
                Cookies::serialize(self::PKCE_COOKIE, '', $this->cookieOpts(0)),
            ],
        ];
    }

    /**
     * Clear the session and get the logout URL.
     *
     * @return array{url: string, cookie: string}
     *   Redirect to `url` and set the `cookie` as a Set-Cookie header to clear the session.
     */
    public function handleLogout(string $returnTo = '/'): array
    {
        return [
            'url'    => $this->client->getLogoutUrl($returnTo),
            'cookie' => Cookies::serialize($this->cookieName, '', $this->cookieOpts(0)),
        ];
    }

    /**
     * Read and decrypt the session from a Cookie header.
     *
     * Returns null when the cookie is absent or the session is invalid/expired.
     */
    public function getSession(string $cookieHeader): ?array
    {
        $cookies = Cookies::parse($cookieHeader);
        $raw     = $cookies[$this->cookieName] ?? null;
        if ($raw === null) {
            return null;
        }
        return Session::decrypt($raw, $this->config['sessionSecret']);
    }

    private function cookieOpts(int $maxAge): array
    {
        return [
            'maxAge'   => $maxAge,
            'httpOnly' => true,
            'sameSite' => 'lax',
            'path'     => '/',
            'secure'   => $this->secure,
        ];
    }

    private function errorRedirect(string $error): array
    {
        return ['redirect' => "/?error={$error}", 'cookies' => []];
    }
}
