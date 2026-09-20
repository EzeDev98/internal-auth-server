package com.internal.auth.feature.identity.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Body for POST /auth/revoke-sessions: which of the calling client's users to sign out. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RevokeSessionsRequest {
    private String username;
}
