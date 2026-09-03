package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Thrown when a caller's clientId/clientSecret (HTTP Basic auth on
 * /api/v1/auth/register, per the multi-tenant redesign) can't be resolved
 * to an enabled client_application - missing/malformed header, unknown
 * clientId, disabled client, public client with no secret, or wrong
 * secret. Deliberately one exception/message for all of those cases, same
 * reasoning as InvalidCredentialsException: no cue to an attacker about
 * which part was wrong.
 */
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class InvalidClientCredentialsException extends RuntimeException {
    public InvalidClientCredentialsException(String message) {
        super(message);
    }
}
