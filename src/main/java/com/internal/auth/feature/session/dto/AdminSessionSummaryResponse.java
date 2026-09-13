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
 *
 * clientId (Step 10B, React Admin Client plan v4): added so a list row
 * carries what DELETE ${app.title}/users/{username}/sessions requires as
 * a required clientId query param - username alone doesn't identify a
 * unique account (see User's class Javadoc, V8), so without this a caller
 * holding only this row couldn't safely revoke it. Same rationale as
 * UserSummaryResponse's clientId field (Step 7A). Purely additive -
 * existing fields and their JSON keys are unchanged.
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
    private String clientId;
}
