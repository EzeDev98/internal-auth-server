package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;

/** Deprecated exception for a failed group-role mapping save. */
@Deprecated(since = "2.0", forRemoval = true)
public class GroupRoleMappingPersistenceException extends PermissionException {
    public GroupRoleMappingPersistenceException(String message, HttpStatus ignored) {
        super(PermissionErrorCode.GROUP_ROLE_MAPPING_FAILED, message);
    }
}
