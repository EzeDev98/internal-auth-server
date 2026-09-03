package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;

/** @deprecated Use {@link PermissionException#alreadyExistsInKeycloak(String)} instead. */
@Deprecated(since = "2.0", forRemoval = true)
public class AlreadyExistInKeycloakException extends PermissionException {
    public AlreadyExistInKeycloakException(String message, HttpStatus ignored) {
        super(PermissionErrorCode.ALREADY_EXISTS_IN_KEYCLOAK, message);
    }
}
