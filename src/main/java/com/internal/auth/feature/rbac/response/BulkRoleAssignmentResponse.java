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
public class BulkRoleAssignmentResponse {
    private int totalRequested;
    private int successfullyAssigned;
    private int skippedDuplicates;
    private int failed;
    private List<UserRoleResponse> assigned;
    private List<String> duplicates;
    private List<String> failures;
}
