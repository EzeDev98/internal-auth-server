package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

/** List row for a role. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RoleSummaryResponse {
    private Long id;
    private String roleName;
    private String description;
    private Long clientApplicationId;
    private LocalDateTime createdAt;
}
