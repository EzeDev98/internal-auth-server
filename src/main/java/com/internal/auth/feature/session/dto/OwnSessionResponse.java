package com.internal.auth.feature.session.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/**
 * One of the CALLER's own sessions, as shown on a "devices signed in" screen.
 * lastUsedAt and expiresAt are derived (see SessionManagementServiceImpl):
 * user_sessions does not record them.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class OwnSessionResponse {
    private String sessionId;
    private String userAgent;
    private String ipAddress;
    private Instant createdAt;
    private Instant lastUsedAt;
    private Instant expiresAt;
    private boolean current;
}
