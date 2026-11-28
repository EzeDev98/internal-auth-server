package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;

/** Deprecated exception for a failed user-role save. */
@Deprecated(since = "2.0", forRemoval = true)
public class UserRolePersistenceException extends PermissionException {
    public UserRolePersistenceException(String message, HttpStatus ignored) {
        super(PermissionErrorCode.USER_ROLE_PERSISTENCE_FAILED, message);
    }
}
