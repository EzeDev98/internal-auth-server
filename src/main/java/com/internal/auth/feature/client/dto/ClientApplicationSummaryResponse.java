package com.internal.auth.feature.client.dto;

import com.internal.auth.feature.client.enums.ClientType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

/**
 * List-row shape for GET ${app.title}/client-applications (Step 2B,
 * React Admin Client plan v4) - never includes the secret or its hash.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ClientApplicationSummaryResponse {
    private Long id;
    private String clientId;
    private String name;
    private ClientType type;
    private boolean enabled;
    private LocalDateTime createdAt;
}
