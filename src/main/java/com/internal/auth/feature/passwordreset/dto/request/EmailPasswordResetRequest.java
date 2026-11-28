package com.internal.auth.feature.passwordreset.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Request body for starting an email-based password reset. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class EmailPasswordResetRequest {
    private String email;
}
