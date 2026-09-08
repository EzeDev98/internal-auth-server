package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

/**
 * List-row shape for GET ${app.title}/roles (Step 2C, React Admin Client
 * plan v4). clientApplicationId is null for a global role - see Role's
 * class Javadoc (Step 13B) on what a non-null value means; nothing in
 * this codebase sets it yet.
 */
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
