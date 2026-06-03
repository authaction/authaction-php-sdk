<?php

namespace AuthAction;

use AuthAction\Exception\TokenExpiredException;
use AuthAction\Exception\TokenInvalidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use UnexpectedValueException;

/**
 * Core JWT verifier.
 *
 * Fetches public keys from /.well-known/jwks.json, caches them in-process,
 * and handles key rotation by busting the cache on an unknown kid.
 */
class JwtVerifier
{
    private ?array $jwksCache = null;

    public function __construct(
        private readonly string $domain,
        private readonly string $audience,
    ) {}

    /**
     * Verify a raw JWT string and return the decoded payload.
     *
     * @return object  Decoded claims.
     * @throws TokenExpiredException  When the token has expired.
     * @throws TokenInvalidException  When the token is invalid.
     */
    public function verify(string $token): object
    {
        $keys = $this->getKeys();

        try {
            $payload = JWT::decode($token, $keys);
        } catch (ExpiredException $e) {
            throw new TokenExpiredException('Token has expired', 0, $e);
        } catch (UnexpectedValueException $e) {
            // kid not found — possible key rotation; bust cache and retry once
            if (str_contains($e->getMessage(), 'kid')) {
                $this->jwksCache = null;
                $keys = $this->getKeys();
                try {
                    $payload = JWT::decode($token, $keys);
                } catch (ExpiredException $e2) {
                    throw new TokenExpiredException('Token has expired', 0, $e2);
                } catch (\Throwable $e2) {
                    throw new TokenInvalidException($e2->getMessage(), 0, $e2);
                }
            } else {
                throw new TokenInvalidException($e->getMessage(), 0, $e);
            }
        } catch (\Throwable $e) {
            throw new TokenInvalidException($e->getMessage(), 0, $e);
        }

        $this->validateClaims($payload);
        return $payload;
    }

    /**
     * Extract the Bearer token from an Authorization header value and verify it.
     *
     * @return object|null  Decoded claims, or null when absent/invalid. Never throws.
     */
    public function verifyRequest(?string $authorizationHeader): ?object
    {
        if ($authorizationHeader === null || !str_starts_with($authorizationHeader, 'Bearer ')) {
            return null;
        }
        $token = trim(substr($authorizationHeader, 7));
        try {
            return $this->verify($token);
        } catch (TokenExpiredException | TokenInvalidException) {
            return null;
        }
    }

    // ── Private ───────────────────────────────────────────────────────────────

    /** @return array<string, Key> */
    private function getKeys(): array
    {
        if ($this->jwksCache === null) {
            $this->jwksCache = $this->fetchJwks();
        }
        return JWK::parseKeySet($this->jwksCache);
    }

    private function fetchJwks(): array
    {
        $uri      = "https://{$this->domain}/.well-known/jwks.json";
        $response = file_get_contents($uri);
        if ($response === false) {
            throw new TokenInvalidException("Failed to fetch JWKS from {$uri}");
        }
        $decoded = json_decode($response, true);
        if (!is_array($decoded)) {
            throw new TokenInvalidException("Invalid JWKS response from {$uri}");
        }
        return $decoded;
    }

    private function validateClaims(object $payload): void
    {
        $iss = $payload->iss ?? null;
        if ($iss !== "https://{$this->domain}") {
            throw new TokenInvalidException("Invalid issuer: {$iss}");
        }
        $aud = isset($payload->aud) ? (array) $payload->aud : [];
        if (!in_array($this->audience, $aud, strict: true)) {
            throw new TokenInvalidException("Invalid audience");
        }
    }
}
