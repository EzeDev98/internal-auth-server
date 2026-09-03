package com.internal.auth.feature.identity.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Request body for POST ${app.title}/mfa/{username} (Step 11E, admin-only). */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class SetMfaRequest {
    private boolean enabled;
}
