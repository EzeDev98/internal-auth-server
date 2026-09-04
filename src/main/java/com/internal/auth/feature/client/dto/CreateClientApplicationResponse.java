package com.internal.auth.feature.client.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Response body for POST ${app.title}/client-applications (Step 10D) and
 * POST ${app.title}/client-applications/{clientId}/rotate-secret (this
 * patch). clientSecret carries the one and only time the raw secret is
 * ever available - only its BCrypt hash is persisted, so if this response
 * is lost, the recovery is calling rotate-secret again, not registering a
 * whole new client application.
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
