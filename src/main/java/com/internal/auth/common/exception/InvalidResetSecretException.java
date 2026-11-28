package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/** Thrown when a tenant wipe request has a missing or invalid reset secret. */
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class InvalidResetSecretException extends RuntimeException {
    public InvalidResetSecretException(String message) {
        super(message);
    }
}
