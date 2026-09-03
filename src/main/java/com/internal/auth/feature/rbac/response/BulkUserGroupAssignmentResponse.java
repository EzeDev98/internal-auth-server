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
public class BulkUserGroupAssignmentResponse {
    private int totalRequested;
    private int successfullyAdded;
    private int alreadyInGroup;
    private int failed;
    private List<UserPermissionGroupResponse> addedMembers;
    private List<UserPermissionGroupResponse> existingMembers;
    private List<String> failures;
}
