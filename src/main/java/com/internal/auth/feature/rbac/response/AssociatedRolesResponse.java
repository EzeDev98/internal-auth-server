package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Roles associated with a group or user. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class AssociatedRolesResponse {

    private Long id;

    private String roleName;

    private String description;

}
