package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class KeycloakSubGroupCreationResponse {
    private int statusCode;
    private String message;
    private String groupName;
    private String description;
    private String parentGroupId;
    private String subGroupId;
}
