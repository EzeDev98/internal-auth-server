package com.internal.auth.feature.identity.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Request body shared by both MFA toggle endpoints: POST
 * ${app.title}/mfa/{username} (MfaAdminController, admin-only) and POST
 * ${app.title}/mfa/self (MfaSelfServiceController, self-service).
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class SetMfaRequest {
    private boolean enabled;
}
