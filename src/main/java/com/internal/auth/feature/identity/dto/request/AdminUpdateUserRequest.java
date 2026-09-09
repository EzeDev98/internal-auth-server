package com.internal.auth.feature.identity.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Request body for PATCH ${app.title}/users/{username} (Step 2A, React
 * Admin Client plan v4). Every field is a nullable Boolean, not a
 * primitive: null means "leave this field unchanged" (true partial-patch
 * semantics), as opposed to false meaning "turn it off".
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AdminUpdateUserRequest {
    private Boolean enabled;
    private Boolean emailVerified;
    private Boolean phoneVerified;
}
