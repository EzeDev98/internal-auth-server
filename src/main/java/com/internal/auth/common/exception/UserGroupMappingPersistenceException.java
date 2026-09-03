package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;

/** @deprecated Use {@link PermissionException#userGroupMappingFailed(String)} instead. */
@Deprecated(since = "2.0", forRemoval = true)
public class UserGroupMappingPersistenceException extends PermissionException {
    public UserGroupMappingPersistenceException(String message, HttpStatus ignored) {
        super(PermissionErrorCode.USER_GROUP_MAPPING_FAILED, message);
    }
}
