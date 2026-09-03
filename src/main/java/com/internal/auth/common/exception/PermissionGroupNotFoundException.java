package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;

/** @deprecated Use {@link PermissionException#permissionGroupNotFound(String)} instead. */
@Deprecated(since = "2.0", forRemoval = true)
public class PermissionGroupNotFoundException extends PermissionException {
    public PermissionGroupNotFoundException(String message, HttpStatus ignored) {
        super(PermissionErrorCode.PERMISSION_GROUP_NOT_FOUND, message);
    }
}
