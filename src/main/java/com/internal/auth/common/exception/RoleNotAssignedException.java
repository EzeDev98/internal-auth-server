package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;

/** @deprecated Use {@link PermissionException#roleNotAssigned(String)} instead. */
@Deprecated(since = "2.0", forRemoval = true)
public class RoleNotAssignedException extends PermissionException {
    public RoleNotAssignedException(String message, HttpStatus ignored) {
        super(PermissionErrorCode.ROLE_NOT_ASSIGNED, message);
    }
}
