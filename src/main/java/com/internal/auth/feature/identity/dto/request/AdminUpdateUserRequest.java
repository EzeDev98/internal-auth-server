package com.internal.auth.feature.identity.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Request body for an admin updating a user's profile. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AdminUpdateUserRequest {
    private Boolean enabled;
    private Boolean emailVerified;
    private Boolean phoneVerified;
}
