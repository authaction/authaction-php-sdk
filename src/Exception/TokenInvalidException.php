<?php

namespace AuthAction\Exception;

/** Thrown when the JWT signature, issuer, audience, or structure is invalid. */
class TokenInvalidException extends AuthActionException {}
