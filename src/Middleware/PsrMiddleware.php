<?php

namespace AuthAction\Middleware;

use AuthAction\JwtVerifier;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * PSR-15 middleware for AuthAction JWT verification.
 *
 * On success, attaches the decoded payload to the request attribute
 * 'authaction.user' and delegates to the next handler.
 * On failure, returns a 401 JSON response.
 *
 * @example Slim 4
 *   $app->add(new PsrMiddleware($verifier, $responseFactory));
 *
 * @example Mezzio
 *   $pipeline->pipe(new PsrMiddleware($verifier, $responseFactory));
 */
class PsrMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly JwtVerifier $verifier,
        private readonly ?ResponseFactoryInterface $responseFactory = null,
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $authHeader = $request->getHeaderLine('Authorization') ?: null;
        $payload = $this->verifier->verifyRequest($authHeader);

        if ($payload === null) {
            return $this->unauthorized($authHeader === null ? 'Missing Bearer token' : 'Invalid token');
        }

        return $handler->handle($request->withAttribute('authaction.user', $payload));
    }

    private function unauthorized(string $message): ResponseInterface
    {
        if ($this->responseFactory === null) {
            throw new \LogicException(
                'PsrMiddleware requires a ResponseFactoryInterface to send 401 responses. ' .
                'Pass one to the constructor.'
            );
        }
        $response = $this->responseFactory->createResponse(401);
        $response = $response->withHeader('Content-Type', 'application/json')
                             ->withHeader('WWW-Authenticate', 'Bearer');
        $response->getBody()->write(json_encode(['error' => 'Unauthorized', 'message' => $message]));
        return $response;
    }
}
