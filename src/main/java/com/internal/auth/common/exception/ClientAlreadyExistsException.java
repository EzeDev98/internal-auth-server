package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Thrown when a ClientApplication's clientId is already registered. Kept
 * separate from UserAlreadyExistsException (documented as specifically
 * about User rows) rather than reused across entity types, matching this
 * codebase's existing one-exception-per-entity convention
 * (UserNotFoundException, etc.).
 */
@ResponseStatus(HttpStatus.CONFLICT)
public class ClientAlreadyExistsException extends RuntimeException {
    public ClientAlreadyExistsException(String message) {
        super(message);
    }
}
