package com.internal.auth.feature.identity.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Request body for POST /api/v1/auth/resend-activation (Step 10C). */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ResendActivationRequest {
    private String email;
}
