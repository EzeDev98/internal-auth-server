package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;

/** Deprecated exception for a role that is not assigned. */
@Deprecated(since = "2.0", forRemoval = true)
public class RoleNotAssignedException extends PermissionException {
    public RoleNotAssignedException(String message, HttpStatus ignored) {
        super(PermissionErrorCode.ROLE_NOT_ASSIGNED, message);
    }
}
