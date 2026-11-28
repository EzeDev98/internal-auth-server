package com.internal.auth.feature.rbac.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Request body for creating or updating a sub-group. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class SubGroupRequest {
    private String groupName;
    private String description;
}
