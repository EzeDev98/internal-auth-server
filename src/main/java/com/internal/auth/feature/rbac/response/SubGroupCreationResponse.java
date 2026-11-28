package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Result of creating a sub-group. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class SubGroupCreationResponse {
    private Long groupId;
    private String groupName;
    private String description;
    private Long superGroupId;
}
