package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Thrown during registration when the requested username, phone number, or
 * email is already taken by an existing User row. Same shape as
 * BadRequestException/UserNotFoundException - a plain RuntimeException with
 * @ResponseStatus doing the HTTP-status mapping, no RestControllerAdvice
 * wiring needed.
 */
@ResponseStatus(HttpStatus.CONFLICT)
public class UserAlreadyExistsException extends RuntimeException {
    public UserAlreadyExistsException(String message) {
        super(message);
    }
}
