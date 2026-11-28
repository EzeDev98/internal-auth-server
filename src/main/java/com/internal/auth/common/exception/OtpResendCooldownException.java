package com.internal.auth.common.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/** Thrown when an OTP resend is requested before the cooldown has elapsed. */
@Getter
@ResponseStatus(HttpStatus.TOO_MANY_REQUESTS)
public class OtpResendCooldownException extends RuntimeException {

    private final long retryAfterSeconds;

    public OtpResendCooldownException(String message, long retryAfterSeconds) {
        super(message);
        this.retryAfterSeconds = retryAfterSeconds;
    }
}
