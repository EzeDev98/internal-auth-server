package com.internal.auth.feature.session.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/**
 * One of the CALLER's own sessions, as shown on a "devices signed in" screen.
 * Step 17h (B-14): one per signed-in device. deviceLabel is "Mac, Chrome";
 * lastActiveAt is the last sign-in or token refresh; current is true for the
 * session whose token made the request. expiresAt is derived from the
 * session's TTL (see SessionManagementServiceImpl).
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class OwnSessionResponse {
    private String sessionId;
    private String deviceLabel;
    private String userAgent;
    private String ipAddress;
    private Instant createdAt;
    private Instant lastActiveAt;
    private Instant expiresAt;
    private boolean current;
}
