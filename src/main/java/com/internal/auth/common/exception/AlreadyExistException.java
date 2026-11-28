package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;

/** Deprecated exception for an entity that already exists. */
@Deprecated(since = "2.0", forRemoval = true)
public class AlreadyExistException extends PermissionException {
    public AlreadyExistException(String message, HttpStatus ignored) {
        super(PermissionErrorCode.ALREADY_EXISTS, message);
    }
}
