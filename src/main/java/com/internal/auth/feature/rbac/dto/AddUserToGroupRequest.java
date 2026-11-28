package com.internal.auth.feature.rbac.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Request body for adding a user to a group. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class AddUserToGroupRequest {
    private String username;
}
