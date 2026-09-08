package com.internal.auth.feature.rbac.service;

import com.internal.auth.feature.rbac.response.RoleDetailResponse;
import com.internal.auth.feature.rbac.response.RoleSummaryResponse;

import java.util.List;

/**
 * Step 2C (React Admin Client plan v4): read-only role directory backing
 * the Roles - List and Roles - Detail screens. Kept separate from
 * PermissionManagementService (which owns role/group creation and
 * assignment) rather than added to that already-large class - this is
 * pure querying, no mutation.
 */
public interface RoleQueryService {

    List<RoleSummaryResponse> listRoles();

    RoleDetailResponse getRoleDetail(Long id);
}
