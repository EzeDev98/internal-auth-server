package com.internal.auth.feature.client.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Set;

/**
 * Request body for POST ${app.title}/client-applications (Step 10D).
 * clientSecret is deliberately not a field here - per the Step 10D
 * decision, the secret is always server-generated, never caller-supplied.
 */
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

    /** null = default (true: strict single-use rotation). false = persistent refresh token. */
    private Boolean refreshTokenRotationEnabled;

    /** Days. Required when refreshTokenRotationEnabled is false; must be omitted otherwise. */
    private Integer refreshTokenTtlDays;

    /** Days from login after which the session ends regardless of activity. Omit for no cap. */
    private Integer refreshTokenMaxLifetimeDays;

    /** null = default (true: a new login revokes every other session for this user+client). false = allow concurrent devices/sessions. */
    private Boolean revokePriorSessionsOnLogin;

    /** null = default (1: one session per user). Above 1 needs revokePriorSessionsOnLogin = false. */
    private Integer maxActiveSessions;

    /** Pre-persistent-refresh-token constructor, kept so existing callers/tests compile unchanged. */
    public CreateClientApplicationRequest(String clientId, String name, String description,
                                          Set<String> redirectUris, Set<String> scopes, Set<String> grantTypes) {
        this(clientId, name, description, redirectUris, scopes, grantTypes, null, null, null, null, null);
    }
}
