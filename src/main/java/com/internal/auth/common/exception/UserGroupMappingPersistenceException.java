package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;

/** Deprecated exception for a failed user-group mapping save. */
@Deprecated(since = "2.0", forRemoval = true)
public class UserGroupMappingPersistenceException extends PermissionException {
    public UserGroupMappingPersistenceException(String message, HttpStatus ignored) {
        super(PermissionErrorCode.USER_GROUP_MAPPING_FAILED, message);
    }
}
