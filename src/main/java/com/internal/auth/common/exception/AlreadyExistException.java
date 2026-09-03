package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;

/** @deprecated Use {@link PermissionException#alreadyExists(String)} instead. */
@Deprecated(since = "2.0", forRemoval = true)
public class AlreadyExistException extends PermissionException {
    public AlreadyExistException(String message, HttpStatus ignored) {
        super(PermissionErrorCode.ALREADY_EXISTS, message);
    }
}
