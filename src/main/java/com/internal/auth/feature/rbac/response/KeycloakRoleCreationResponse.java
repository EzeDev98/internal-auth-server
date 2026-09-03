package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class KeycloakRoleCreationResponse {
    private int statusCode;
    private String message;
    private String roleName;
    private String description;
    private String keycloakRoleId;
}
