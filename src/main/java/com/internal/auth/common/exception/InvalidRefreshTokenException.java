package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Step 15C - thrown by LoginServiceImpl#refreshToken for a missing,
 * unknown, expired, invalidated, or wrong-client refresh token.
 * Deliberately the same message for all of those cases (mirroring
 * InvalidCredentialsException's reasoning) - a caller shouldn't be able to
 * distinguish "this refresh token never existed" from "it existed but
 * belongs to a different client application" from "it existed but already
 * expired", since any of those distinctions is a hint for someone probing
 * with a stolen or guessed token.
 */
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class InvalidRefreshTokenException extends RuntimeException {
    public InvalidRefreshTokenException(String message) {
        super(message);
    }
}