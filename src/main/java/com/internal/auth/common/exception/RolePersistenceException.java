package com.internal.auth.common.exception;

import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;

/** @deprecated Use {@link PermissionException#rolePersistenceFailed(String)} instead. */
@Deprecated(since = "2.0", forRemoval = true)
public class RolePersistenceException extends PermissionException {
    public RolePersistenceException(String message, DataAccessException cause, HttpStatus ignored) {
        super(PermissionErrorCode.ROLE_PERSISTENCE_FAILED, message, cause);
    }
}
