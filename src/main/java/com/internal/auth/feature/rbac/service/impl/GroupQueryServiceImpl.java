package com.internal.auth.feature.rbac.service.impl;

import com.internal.auth.common.exception.PermissionException;
import com.internal.auth.feature.rbac.model.PermissionGroup;
import com.internal.auth.feature.rbac.model.SubPermissionGroup;
import com.internal.auth.feature.rbac.repository.PermissionGroupsRepository;
import com.internal.auth.feature.rbac.repository.SubPermissionGroupRepository;
import com.internal.auth.feature.rbac.response.GroupSummaryResponse;
import com.internal.auth.feature.rbac.response.SubGroupSummaryResponse;
import com.internal.auth.feature.rbac.service.GroupQueryService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class GroupQueryServiceImpl implements GroupQueryService {

    private final PermissionGroupsRepository permissionGroupsRepository;
    private final SubPermissionGroupRepository subPermissionGroupRepository;

    @Override
    @Transactional(readOnly = true)
    public List<GroupSummaryResponse> listTopLevelGroups() {
        return permissionGroupsRepository.findAll().stream()
                .map(this::toSummary)
                .toList();
    }

    @Override
    @Transactional(readOnly = true)
    public List<SubGroupSummaryResponse> listSubgroups(Long parentGroupId) {
        PermissionGroup parentGroup = permissionGroupsRepository.findById(parentGroupId)
                .orElseThrow(() -> PermissionException.groupNotFound("Group not found: id=" + parentGroupId));

        return subPermissionGroupRepository.findAllByParentGroup(parentGroup).stream()
                .map(this::toSummary)
                .toList();
    }

    private GroupSummaryResponse toSummary(PermissionGroup group) {
        return new GroupSummaryResponse(
                group.getId(),
                group.getGroupName(),
                group.getDescription(),
                group.getClientApplication() == null ? null : group.getClientApplication().getId(),
                group.getCreatedAt());
    }

    private SubGroupSummaryResponse toSummary(SubPermissionGroup subGroup) {
        return new SubGroupSummaryResponse(
                subGroup.getId(),
                subGroup.getGroupName(),
                subGroup.getDescription(),
                subGroup.getParentGroup().getId(),
                subGroup.getCreatedAt());
    }
}
