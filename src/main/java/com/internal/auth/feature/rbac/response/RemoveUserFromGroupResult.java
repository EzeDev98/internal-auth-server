package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Result of removing a user from a group. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RemoveUserFromGroupResult {
    private String username;
    private String roleName;
}
