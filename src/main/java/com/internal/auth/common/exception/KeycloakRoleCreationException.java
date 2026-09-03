package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;

/** @deprecated Use {@link PermissionException#keycloakRoleCreationFailed(String)} instead. */
@Deprecated(since = "2.0", forRemoval = true)
public class KeycloakRoleCreationException extends PermissionException {
    public KeycloakRoleCreationException(String message, HttpStatus ignored) {
        super(PermissionErrorCode.KEYCLOAK_ROLE_CREATION_FAILED, message);
    }
}
