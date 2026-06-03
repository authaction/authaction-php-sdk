<?php

namespace AuthAction\Exception;

/** Thrown when the JWT exp claim is in the past. */
class TokenExpiredException extends AuthActionException {}
