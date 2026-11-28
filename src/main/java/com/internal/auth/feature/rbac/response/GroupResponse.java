package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

/** Group details. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class GroupResponse {

    private Long groupId;

    private String groupName;

    private String description;


    private List<GroupedUserResponse> userResponses;

    private List<AssociatedRolesResponse> roles;
}
