package com.internal.auth.feature.client.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Set;

/**
 * Request body for PATCH ${app.title}/client-applications/{clientId}
 * (Step 2B, React Admin Client plan v4). Null fields are left unchanged;
 * redirectUris/scopes are replaced wholesale when non-null (an empty set
 * clears them), not merged - same partial-patch convention as
 * AdminUpdateUserRequest (Step 2A). The secret is not editable here. grantTypes, when
 * non-null, replaces the set wholesale, subject to the safeguards in
 * ClientApplicationServiceImpl#validateGrantTypes.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UpdateClientApplicationRequest {
    private String name;
    private String description;
    private Set<String> redirectUris;
    private Set<String> scopes;
    private Boolean enabled;
    private Boolean refreshTokenRotationEnabled;
    private Integer refreshTokenTtlDays;
    private Integer refreshTokenMaxLifetimeDays;
    private Boolean revokePriorSessionsOnLogin;
    private Set<String> grantTypes;
}
