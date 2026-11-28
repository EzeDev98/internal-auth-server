package com.internal.auth.feature.client.dto;

import com.internal.auth.feature.client.enums.ClientType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.Set;

/** Detail view of a single client application. */
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
    private int maxActiveSessions;
}
