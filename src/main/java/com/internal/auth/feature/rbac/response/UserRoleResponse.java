package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** A user's role assignment. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserRoleResponse {
    private Long id;
    private Long userId;
    private Long roleId;
}
