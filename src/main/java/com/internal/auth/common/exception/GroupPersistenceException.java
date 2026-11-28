package com.internal.auth.common.exception;

import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;

/** Deprecated exception for a failed group save. */
@Deprecated(since = "2.0", forRemoval = true)
public class GroupPersistenceException extends PermissionException {
    public GroupPersistenceException(String message, DataAccessException cause, HttpStatus ignored) {
        super(PermissionErrorCode.GROUP_PERSISTENCE_FAILED, message, cause);
    }
}
