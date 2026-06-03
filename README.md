# authaction-php-sdk

AuthAction JWT verification SDK for PHP 8.1+. Works with **Laravel**, **PSR-15** frameworks (Slim, Mezzio), and plain PHP.

## Installation

```bash
composer require authaction/authaction-php-sdk
```

## Quick start

```php
use AuthAction\AuthAction;

$aa = new AuthAction(
    domain:   $_ENV['AUTHACTION_DOMAIN'],
    audience: $_ENV['AUTHACTION_AUDIENCE'],
);

// Verify a raw token — throws TokenExpiredException / TokenInvalidException on failure
$payload = $aa->verifyToken($token);
echo $payload->sub;

// Verify from Authorization header — returns null on missing/invalid
$payload = $aa->verifyRequest($_SERVER['HTTP_AUTHORIZATION'] ?? null);
```

## Laravel

```php
// bootstrap/app.php
->withMiddleware(function (Middleware $middleware) {
    $middleware->alias(['auth.jwt' => \AuthAction\Middleware\LaravelMiddleware::class]);
})

// routes/api.php
Route::middleware('auth.jwt')->get('/me', function (Request $request) {
    $user = $request->get('authaction.user');
    return ['sub' => $user->sub];
});
```

Register `AuthAction` as a singleton in a ServiceProvider:

```php
$this->app->singleton(AuthAction::class, fn () =>
    new AuthAction(config('authaction.domain'), config('authaction.audience'))
);
```

## PSR-15 (Slim, Mezzio)

```php
use AuthAction\Middleware\PsrMiddleware;
use Slim\Factory\AppFactory;

$app = AppFactory::create();
$app->add(new PsrMiddleware($verifier, $responseFactory));

$app->get('/protected', function (Request $request, Response $response) {
    $user = $request->getAttribute('authaction.user');
    $response->getBody()->write(json_encode(['sub' => $user->sub]));
    return $response;
});
```

## Exceptions

```php
use AuthAction\Exception\TokenExpiredException;
use AuthAction\Exception\TokenInvalidException;

try {
    $payload = $aa->verifyToken($token);
} catch (TokenExpiredException $e) {
    http_response_code(401);
    echo json_encode(['error' => 'Token has expired']);
} catch (TokenInvalidException $e) {
    http_response_code(401);
    echo json_encode(['error' => $e->getMessage()]);
}
```

## Environment variables

```bash
AUTHACTION_DOMAIN=your-tenant.eu.authaction.com
AUTHACTION_AUDIENCE=https://api.your-app.com
```

## License

MIT
