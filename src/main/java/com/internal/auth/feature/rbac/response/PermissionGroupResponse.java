package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Permission group details. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class PermissionGroupResponse {

    private Long groupId;
    private String groupName;
    private String description;
}
