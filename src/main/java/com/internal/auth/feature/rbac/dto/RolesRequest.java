package com.internal.auth.feature.rbac.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Request body carrying a list of roles. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class RolesRequest {
    private String roleName;
    private String description;
}
