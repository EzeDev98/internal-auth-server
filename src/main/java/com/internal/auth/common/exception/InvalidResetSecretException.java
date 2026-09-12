package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Thrown by {@link com.internal.auth.feature.admin.security.TenantResetAuthorizer}
 * when the caller's X-Reset-Secret header is missing/invalid, or when the
 * tenant-wipe endpoint is disabled entirely (no admin.reset.secret configured).
 * Mirrors SyncPoint's own UnauthorizedException usage for its local
 * /admin/reset/wipe endpoint - same guard, same status, same "don't tell the
 * caller which part was wrong" posture as InvalidClientCredentialsException.
 */
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class InvalidResetSecretException extends RuntimeException {
    public InvalidResetSecretException(String message) {
        super(message);
    }
}
