package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;

/** Deprecated exception for a failed role assignment. */
@Deprecated(since = "2.0", forRemoval = true)
public class RoleAssignmentException extends PermissionException {
    public RoleAssignmentException(String message, HttpStatus ignored) {
        super(PermissionErrorCode.ROLE_ASSIGNMENT_FAILED, message);
    }
}
