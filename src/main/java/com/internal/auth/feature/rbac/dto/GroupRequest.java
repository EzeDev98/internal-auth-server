package com.internal.auth.feature.rbac.dto;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Request body for creating or updating a group. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class GroupRequest {
    private String groupName;
    private String description;
}
