package com.internal.auth.feature.client.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Response body for POST ${app.title}/client-applications (Step 10D).
 * clientSecret carries the one and only time the raw secret is ever
 * available - only its BCrypt hash is persisted, so if this response is
 * lost, the only recovery is issuing a new secret (rotation isn't built
 * yet - out of scope per the Step 10D "create + verify only" decision).
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CreateClientApplicationResponse {
    private Long id;
    private String clientId;
    private String clientSecret;
    private String name;
    private String message;
}
