package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

/** List row for a sub-group. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class SubGroupSummaryResponse {
    private Long id;
    private String groupName;
    private String description;
    private Long parentGroupId;
    private LocalDateTime createdAt;
}
