package com.internal.auth.feature.rbac.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

/** Request body for assigning roles in bulk. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class BulkRoleAssignmentRequest {
    private List<String> usernames;
    private List<String> roles;
}
