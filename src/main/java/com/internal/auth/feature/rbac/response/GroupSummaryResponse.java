package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

/** List row for a group. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class GroupSummaryResponse {
    private Long id;
    private String groupName;
    private String description;
    private Long clientApplicationId;
    private LocalDateTime createdAt;
}
