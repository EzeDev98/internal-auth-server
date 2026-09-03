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
}
