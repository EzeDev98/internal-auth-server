package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;

/** @deprecated Use {@link PermissionException#groupCreationFailed(String)} instead. */
@Deprecated(since = "2.0", forRemoval = true)
public class GroupCreationException extends PermissionException {
    public GroupCreationException(String message, HttpStatus ignored) {
        super(PermissionErrorCode.GROUP_CREATION_FAILED, message);
    }
}
