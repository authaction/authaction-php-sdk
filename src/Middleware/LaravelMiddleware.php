<?php

namespace AuthAction\Middleware;

use AuthAction\AuthAction;
use AuthAction\Exception\TokenExpiredException;
use AuthAction\Exception\TokenInvalidException;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Laravel middleware for AuthAction JWT verification.
 *
 * Register in bootstrap/app.php:
 *   ->withMiddleware(function (Middleware $middleware) {
 *       $middleware->alias(['auth.jwt' => \AuthAction\Middleware\LaravelMiddleware::class]);
 *   })
 *
 * Use in routes:
 *   Route::middleware('auth.jwt')->get('/protected', fn (Request $r) => $r->get('authaction.user'));
 *
 * The decoded payload is available via $request->get('authaction.user').
 */
class LaravelMiddleware
{
    public function __construct(private readonly AuthAction $authAction) {}

    public function handle(Request $request, Closure $next): Response
    {
        $authHeader = $request->header('Authorization');

        if (!$authHeader || !str_starts_with($authHeader, 'Bearer ')) {
            return response()->json(['error' => 'Unauthorized', 'message' => 'Missing Bearer token'], 401);
        }

        $token = trim(substr($authHeader, 7));
        try {
            $payload = $this->authAction->verifyToken($token);
            $request->attributes->set('authaction.user', $payload);
        } catch (TokenExpiredException) {
            return response()->json(['error' => 'Unauthorized', 'message' => 'Token has expired'], 401);
        } catch (TokenInvalidException $e) {
            return response()->json(['error' => 'Unauthorized', 'message' => $e->getMessage()], 401);
        }

        return $next($request);
    }
}
