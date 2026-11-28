package com.internal.auth.feature.client.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Set;

/** Request body for creating a client application. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CreateClientApplicationRequest {
    private String clientId;
    private String name;
    private String description;
    private Set<String> redirectUris;
    private Set<String> scopes;
    private Set<String> grantTypes;

    private Boolean refreshTokenRotationEnabled;

    private Integer refreshTokenTtlDays;

    private Integer refreshTokenMaxLifetimeDays;

    private Boolean revokePriorSessionsOnLogin;

    private Integer maxActiveSessions;

    public CreateClientApplicationRequest(String clientId, String name, String description,
                                          Set<String> redirectUris, Set<String> scopes, Set<String> grantTypes) {
        this(clientId, name, description, redirectUris, scopes, grantTypes, null, null, null, null, null);
    }
}
