<?php

declare(strict_types=1);

namespace AuthAction;

final class Cookies
{
    /** Parse a Cookie header string into a name→value map. */
    public static function parse(string $header): array
    {
        $result = [];
        foreach (explode(';', $header) as $part) {
            $pair = explode('=', trim($part), 2);
            $name = trim($pair[0]);
            if ($name !== '') {
                $result[$name] = isset($pair[1]) ? trim($pair[1]) : '';
            }
        }
        return $result;
    }

    /** Serialize a Set-Cookie header value. */
    public static function serialize(string $name, string $value, array $opts = []): string
    {
        $cookie = "{$name}={$value}";
        if (array_key_exists('maxAge', $opts)) {
            $cookie .= '; Max-Age=' . (int) $opts['maxAge'];
        }
        if (!empty($opts['path'])) {
            $cookie .= '; Path=' . $opts['path'];
        }
        if (!empty($opts['httpOnly'])) {
            $cookie .= '; HttpOnly';
        }
        if (!empty($opts['sameSite'])) {
            $cookie .= '; SameSite=' . ucfirst((string) $opts['sameSite']);
        }
        if (!empty($opts['secure'])) {
            $cookie .= '; Secure';
        }
        return $cookie;
    }
}
