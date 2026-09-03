package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class SubGroupResponse {

    private Long subGroupId;

    private String subgroupName;

    private String description;

    private String subgroupKeycloakGroupId;

    private List<GroupedUserResponse> userResponses;

    private List<AssociatedRolesResponse> roles;
}
