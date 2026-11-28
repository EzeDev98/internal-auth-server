package com.internal.auth.feature.rbac.service;

import com.internal.auth.feature.rbac.response.RoleDetailResponse;
import com.internal.auth.feature.rbac.response.RoleSummaryResponse;

import java.util.List;

/** Read-only queries for roles. */
public interface RoleQueryService {

    List<RoleSummaryResponse> listRoles();

    RoleDetailResponse getRoleDetail(Long id);
}
