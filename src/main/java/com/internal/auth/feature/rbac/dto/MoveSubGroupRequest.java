package com.internal.auth.feature.rbac.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Request body for moving a sub-group to another parent. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class MoveSubGroupRequest {
    private String newParentGroupName;
}
