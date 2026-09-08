package com.internal.auth.feature.client.dto;

import com.internal.auth.feature.client.enums.ClientType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.Set;

/**
 * Single-client detail shape for GET/PATCH
 * ${app.title}/client-applications/{clientId} (Step 2B, React Admin
 * Client plan v4). Never includes the secret or its hash - only ever
 * returned once, at creation/rotation time (see
 * CreateClientApplicationResponse).
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ClientApplicationDetailResponse {
    private Long id;
    private String clientId;
    private String name;
    private String description;
    private Set<String> redirectUris;
    private Set<String> scopes;
    private Set<String> grantTypes;
    private ClientType type;
    private boolean enabled;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
