package com.internal.auth.feature.client.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Response for creating a client application or rotating its secret. */
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
