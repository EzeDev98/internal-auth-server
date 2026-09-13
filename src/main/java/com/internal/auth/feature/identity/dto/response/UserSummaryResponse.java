package com.internal.auth.feature.identity.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

/**
 * List-row shape for GET ${app.title}/users (Step 2A, React Admin Client
 * plan v4) - deliberately lighter than UserProfileResponse (no verified
 * flags), matching what the Users - List screen's table actually renders.
 *
 * clientId (Step 7A, React Admin Client plan v4): added so a list row
 * carries what GET/PATCH ${app.title}/users/{username} requires as a
 * required clientId query param - username is only unique per
 * client_application_id (see User's class Javadoc, V8), so without this a
 * caller holding only this row couldn't safely resolve back to one user.
 * Purely additive - existing fields and their JSON keys are unchanged.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserSummaryResponse {
    private Long id;
    private String username;
    private String phoneNumber;
    private String email;
    private boolean enabled;
    private boolean mfaEnabled;
    private LocalDateTime createdAt;
    private String clientId;
}
