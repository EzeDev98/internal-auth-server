package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;

/** Deprecated exception for a missing entity. */
@Deprecated(since = "2.0", forRemoval = true)
public class NotFoundException extends PermissionException {
    public NotFoundException(String message, HttpStatus ignored) {
        super(PermissionErrorCode.GROUP_NOT_FOUND, message);
    }
}
