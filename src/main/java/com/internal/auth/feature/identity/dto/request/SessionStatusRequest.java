package com.internal.auth.feature.identity.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Body for POST /auth/session-status: which of the calling client's users to check. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class SessionStatusRequest {
    private String username;
}
