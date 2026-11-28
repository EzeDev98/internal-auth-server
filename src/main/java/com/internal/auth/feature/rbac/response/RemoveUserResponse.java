package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Result of removing a user. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class RemoveUserResponse {
    private int statusCode;
    private String message;
    private String username;
    private String groupName;
}
