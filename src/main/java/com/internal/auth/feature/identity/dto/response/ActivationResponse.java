package com.internal.auth.feature.identity.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Response for account activation and resend requests. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ActivationResponse {
    private String message;
}
