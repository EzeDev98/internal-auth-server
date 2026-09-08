package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

/**
 * List-row shape for GET ${app.title}/groups/{id}/subgroups (Step 2D,
 * React Admin Client plan v4).
 */
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
