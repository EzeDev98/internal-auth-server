package com.internal.auth.feature.session.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/** One of the caller's own signed-in sessions. */
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
