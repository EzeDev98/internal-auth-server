package com.internal.auth.feature.rbac.service;

import com.internal.auth.feature.rbac.response.GroupSummaryResponse;
import com.internal.auth.feature.rbac.response.SubGroupSummaryResponse;

import java.util.List;

/**
 * Step 2D (React Admin Client plan v4): read-only group directory backing
 * the Groups - Tree view screen. Kept separate from PermissionManagementService
 * (creation/assignment/deletion) and PermissionEntityService (existing
 * fetch-by-name endpoints) - this is new, purely additive querying by id,
 * for exactly the "I don't know the names yet" gap those name-keyed
 * endpoints can't solve on their own.
 */
public interface GroupQueryService {

    List<GroupSummaryResponse> listTopLevelGroups();

    /**
     * Throws PermissionException (groupNotFound, 404) if parentGroupId
     * doesn't resolve to an existing top-level group.
     */
    List<SubGroupSummaryResponse> listSubgroups(Long parentGroupId);
}
