package com.internal.auth.common.exception;

import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;

/** Deprecated exception for a failed sub-group save. */
@Deprecated(since = "2.0", forRemoval = true)
public class SubGroupPersistenceException extends PermissionException {
    public SubGroupPersistenceException(String message, DataAccessException cause, HttpStatus ignored) {
        super(PermissionErrorCode.SUB_GROUP_PERSISTENCE_FAILED, message, cause);
    }
}
