package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;

/** Deprecated exception for a missing permission group. */
@Deprecated(since = "2.0", forRemoval = true)
public class PermissionGroupNotFoundException extends PermissionException {
    public PermissionGroupNotFoundException(String message, HttpStatus ignored) {
        super(PermissionErrorCode.PERMISSION_GROUP_NOT_FOUND, message);
    }
}
