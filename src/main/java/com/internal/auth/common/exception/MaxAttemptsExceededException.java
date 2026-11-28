package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/** Thrown when the maximum number of OTP attempts has been exceeded. */
@ResponseStatus(HttpStatus.TOO_MANY_REQUESTS)
public class MaxAttemptsExceededException extends RuntimeException {
    public MaxAttemptsExceededException(String message) {
        super(message);
    }
}
