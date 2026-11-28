package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Role details. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class RoleResponse {

    private int statusCode;
    private Long roleId;
    private String roleName;
    private String description;
}
