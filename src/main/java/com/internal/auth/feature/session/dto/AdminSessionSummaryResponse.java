package com.internal.auth.feature.session.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

/**
 * List-row shape for GET ${app.title}/admin/sessions (Step 2E, React
 * Admin Client plan v4). ipAddress/device are null for any session
 * created before this step - see UserSession's class Javadoc.
 */
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
}
