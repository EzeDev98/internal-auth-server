package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;

/** Deprecated exception for a user that could not be added to a group. */
@Deprecated(since = "2.0", forRemoval = true)
public class UserNotAddedTOGroupException extends PermissionException {
    public UserNotAddedTOGroupException(String message, HttpStatus ignored) {
        super(PermissionErrorCode.USER_NOT_ADDED_TO_GROUP, message);
    }
}
