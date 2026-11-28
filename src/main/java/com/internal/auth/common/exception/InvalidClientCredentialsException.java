package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/** Thrown when a caller's client credentials do not match an enabled client application. */
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class InvalidClientCredentialsException extends RuntimeException {
    public InvalidClientCredentialsException(String message) {
        super(message);
    }
}
