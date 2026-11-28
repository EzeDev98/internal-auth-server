package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/** Thrown when a refresh token is missing, unknown, expired, invalidated or issued to another client. */
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class InvalidRefreshTokenException extends RuntimeException {
    public InvalidRefreshTokenException(String message) {
        super(message);
    }
}
