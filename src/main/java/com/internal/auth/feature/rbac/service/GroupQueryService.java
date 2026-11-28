package com.internal.auth.feature.rbac.service;

import com.internal.auth.feature.rbac.response.GroupSummaryResponse;
import com.internal.auth.feature.rbac.response.SubGroupSummaryResponse;

import java.util.List;

/** Read-only queries for groups and sub-groups. */
public interface GroupQueryService {

    List<GroupSummaryResponse> listTopLevelGroups();

    List<SubGroupSummaryResponse> listSubgroups(Long parentGroupId);
}
