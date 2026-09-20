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
 * Client plan v4). clientSecret (added for the admin console's Keycloak-
 * style Credentials field) is the decrypted contents of
 * ClientApplication.clientSecretEncrypted when present - null for PUBLIC
 * clients and for any CONFIDENTIAL client that predates that column,
 * which must be rotated to get a viewable secret. This is a deliberate,
 * narrow exception to "never expose stored credential material" - see
 * ClientApplication's javadoc on clientSecretEncrypted for why it's safe:
 * this value is never used for authentication, only decrypted for
 * display to an already-authenticated admin.
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
    private String clientSecret;
    private boolean refreshTokenRotationEnabled;
    private Integer refreshTokenTtlDays;
    private Integer refreshTokenMaxLifetimeDays;
    private boolean revokePriorSessionsOnLogin;
}
