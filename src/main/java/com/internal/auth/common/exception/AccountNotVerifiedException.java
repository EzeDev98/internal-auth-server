package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Thrown by LoginServiceImpl when Step 10E's verification gate isn't
 * satisfied - only reached after the password is already confirmed
 * correct. See User's class Javadoc for the exact per-field gate rule this
 * enforces.
 */
@ResponseStatus(HttpStatus.FORBIDDEN)
public class AccountNotVerifiedException extends RuntimeException {
    public AccountNotVerifiedException(String message) {
        super(message);
    }
}
