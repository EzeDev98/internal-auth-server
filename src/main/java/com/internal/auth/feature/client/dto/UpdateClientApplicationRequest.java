package com.internal.auth.feature.client.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Set;

/** Request body for updating a client application. */
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
    private Integer maxActiveSessions;
}
