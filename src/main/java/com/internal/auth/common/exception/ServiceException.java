package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;

/** Deprecated generic service exception. */
@Deprecated(since = "2.0", forRemoval = true)
public class ServiceException extends PermissionException {
    public ServiceException(String message, HttpStatus ignored) {
        super(PermissionErrorCode.INTERNAL_ERROR, message);
    }
}
