package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;

/** Deprecated exception for a missing group. */
@Deprecated(since = "2.0", forRemoval = true)
public class GroupNotFoundException extends PermissionException {
    public GroupNotFoundException(String message, HttpStatus ignored) {
        super(PermissionErrorCode.GROUP_NOT_FOUND, message);
    }
}
