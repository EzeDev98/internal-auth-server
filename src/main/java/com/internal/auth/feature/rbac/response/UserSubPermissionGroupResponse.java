package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** A user's sub-group membership. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserSubPermissionGroupResponse {

    private Long id;
    private Long userId;
    private Long groupId;
    private Long subGroupId;
}
