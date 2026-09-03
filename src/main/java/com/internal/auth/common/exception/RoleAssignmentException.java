package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;

/** @deprecated Use {@link PermissionException#roleAssignmentFailed(String)} instead. */
@Deprecated(since = "2.0", forRemoval = true)
public class RoleAssignmentException extends PermissionException {
    public RoleAssignmentException(String message, HttpStatus ignored) {
        super(PermissionErrorCode.ROLE_ASSIGNMENT_FAILED, message);
    }
}
