package com.internal.auth.feature.rbac.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

/** Request body for adding several users to a group. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class AddUsersToGroupRequest {
    private List<String> usernames;
}
