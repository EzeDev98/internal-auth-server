package com.internal.auth.feature.passwordreset.constants;

import lombok.Getter;
import lombok.Setter;

/** Reset token settings for the password reset flow. */
@Getter
@Setter
public class PasswordToken {
    private int expirationMinutes = 10;
}
