package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;

/** Deprecated exception for a failed group creation. */
@Deprecated(since = "2.0", forRemoval = true)
public class GroupCreationException extends PermissionException {
    public GroupCreationException(String message, HttpStatus ignored) {
        super(PermissionErrorCode.GROUP_CREATION_FAILED, message);
    }
}
