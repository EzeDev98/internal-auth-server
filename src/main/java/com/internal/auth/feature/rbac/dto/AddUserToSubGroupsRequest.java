package com.internal.auth.feature.rbac.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

/** Request body for adding a user to several sub-groups. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class AddUserToSubGroupsRequest {
    private List<String> subGroupNames;
}
