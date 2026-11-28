package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;

/** Deprecated exception for a missing role. */
@Deprecated(since = "2.0", forRemoval = true)
public class RoleNotFoundException extends PermissionException {
    public RoleNotFoundException(String message, HttpStatus ignored) {
        super(PermissionErrorCode.ROLE_NOT_FOUND, message);
    }
}
