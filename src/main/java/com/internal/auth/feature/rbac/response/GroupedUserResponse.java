package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Users belonging to a group. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class GroupedUserResponse {
    private Long userId;
    private String username;
    private String email;

    private String membership;
}
