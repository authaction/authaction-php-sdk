<?php

declare(strict_types=1);

namespace AuthAction;

final class Session
{
    private const CIPHER     = 'aes-256-gcm';
    private const TAG_LENGTH = 16;
    private const IV_LENGTH  = 12;

    /**
     * Encrypt session data into a compact AES-256-GCM token.
     *
     * Format: base64url(iv).base64url(ciphertext).base64url(tag)
     * Key: SHA-256 of the secret (32 bytes, correct for AES-256-GCM).
     */
    public static function encrypt(array $data, string $secret, int $maxAgeSeconds = 604800): string
    {
        $key = self::deriveKey($secret);
        $iv  = random_bytes(self::IV_LENGTH);

        $payload = json_encode(array_merge($data, [
            'iat' => time(),
            'exp' => time() + $maxAgeSeconds,
        ]), JSON_THROW_ON_ERROR);

        $tag        = '';
        $ciphertext = openssl_encrypt(
            $payload,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            self::TAG_LENGTH,
        );

        if ($ciphertext === false) {
            throw new \RuntimeException('Session encryption failed');
        }

        return implode('.', [self::b64u($iv), self::b64u($ciphertext), self::b64u($tag)]);
    }

    /** Decrypt a session token. Returns null on any failure (invalid format, wrong key, expired). */
    public static function decrypt(string $token, string $secret): ?array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return null;
        }

        try {
            $key        = self::deriveKey($secret);
            $iv         = self::b64uDecode($parts[0]);
            $ciphertext = self::b64uDecode($parts[1]);
            $tag        = self::b64uDecode($parts[2]);
        } catch (\Throwable) {
            return null;
        }

        $plaintext = openssl_decrypt($ciphertext, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv, $tag);
        if ($plaintext === false) {
            return null;
        }

        try {
            $data = json_decode($plaintext, associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            return null;
        }

        if (isset($data['exp']) && $data['exp'] < time()) {
            return null;
        }

        return $data;
    }

    private static function deriveKey(string $secret): string
    {
        return hash('sha256', $secret, binary: true);
    }

    private static function b64u(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function b64uDecode(string $data): string
    {
        $result = base64_decode(strtr($data, '-_', '+/'), strict: true);
        if ($result === false) {
            throw new \InvalidArgumentException('Invalid base64url');
        }
        return $result;
    }
}
