package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class KeycloakGroupRoleAssignmentResponse {
    private String message;
    private int statusCode;
    private String groupName;
    private String roleName;
}
