package com.internal.auth.feature.identity.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Request body for checking a user's session status. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class SessionStatusRequest {
    private String username;
}
