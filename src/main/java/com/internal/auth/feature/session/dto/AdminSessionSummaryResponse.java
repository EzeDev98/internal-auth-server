package com.internal.auth.feature.session.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

/** List row for a session in the admin view. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AdminSessionSummaryResponse {
    private Long id;
    private Long userId;
    private String username;
    private String ipAddress;
    private String device;
    private boolean active;
    private LocalDateTime createdAt;
    private LocalDateTime endedAt;
    private String endReason;
    private String clientId;
}
