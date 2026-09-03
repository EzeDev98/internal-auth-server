package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;

/** @deprecated Use {@link PermissionException#keycloakGroupCreationFailed(String)} instead. */
@Deprecated(since = "2.0", forRemoval = true)
public class KeycloakGroupCreationException extends PermissionException {
    public KeycloakGroupCreationException(String message, HttpStatus ignored) {
        super(PermissionErrorCode.KEYCLOAK_GROUP_CREATION_FAILED, message);
    }
}
