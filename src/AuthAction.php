<?php

namespace AuthAction;

use AuthAction\Exception\TokenExpiredException;
use AuthAction\Exception\TokenInvalidException;
use AuthAction\Middleware\LaravelMiddleware;
use AuthAction\Middleware\PsrMiddleware;

/**
 * Top-level AuthAction client.
 *
 * Framework-agnostic entry point. Works with plain PHP, Laravel, and any
 * PSR-15 compatible framework (Slim, Mezzio, etc.).
 *
 * @example Plain PHP
 *   $aa = new AuthAction('myapp.eu.authaction.com', 'https://api.myapp.com');
 *   $user = $aa->verifyToken($_SERVER['HTTP_AUTHORIZATION'] ?? null);
 *
 * @example Laravel — register in bootstrap/app.php or a ServiceProvider
 *   $aa = new AuthAction(env('AUTHACTION_DOMAIN'), env('AUTHACTION_AUDIENCE'));
 *   // Then use $aa->laravelMiddleware() or bind via the container.
 */
class AuthAction
{
    private readonly JwtVerifier $verifier;

    public function __construct(string $domain, string $audience)
    {
        $this->verifier = new JwtVerifier($domain, $audience);
    }

    /**
     * Verify a raw JWT string.
     *
     * @throws TokenExpiredException
     * @throws TokenInvalidException
     */
    public function verifyToken(string $token): object
    {
        return $this->verifier->verify($token);
    }

    /**
     * Verify from an Authorization header value. Returns null on missing/invalid.
     */
    public function verifyRequest(?string $authorizationHeader): ?object
    {
        return $this->verifier->verifyRequest($authorizationHeader);
    }

    /**
     * Alias for verifyRequest — verify from an Authorization header value.
     */
    public function verifyFromHeader(?string $authorizationHeader): ?object
    {
        return $this->verifier->verifyRequest($authorizationHeader);
    }

    /**
     * Factory: create an AuthActionClient from a config array.
     */
    public static function createClient(array $config): AuthActionClient
    {
        return new AuthActionClient($config);
    }

    /**
     * Factory: create an Auth instance from a config array.
     */
    public static function createAuth(array $config): Auth
    {
        return new Auth($config);
    }

    /**
     * Returns a configured PSR-15 middleware instance.
     */
    public function psrMiddleware(): PsrMiddleware
    {
        return new PsrMiddleware($this->verifier);
    }

    /**
     * Returns the FQCN of the Laravel middleware.
     * Bind $aa as a singleton first, then use this in route definitions.
     */
    public function laravelMiddleware(): string
    {
        return LaravelMiddleware::class;
    }
}
