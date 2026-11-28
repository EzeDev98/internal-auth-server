package com.internal.auth.feature.rbac.service.impl;

import com.internal.auth.common.exception.PermissionErrorCode;
import com.internal.auth.common.exception.PermissionException;
import com.internal.auth.feature.rbac.model.PermissionGroup;
import com.internal.auth.feature.rbac.model.Role;
import com.internal.auth.feature.rbac.model.RolePermissionGroupMapping;
import com.internal.auth.feature.rbac.response.RoleAndPermissionGroupMappingResponse;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Unit tests for GroupRoleServiceImpl. */
class GroupRoleServiceImplTest {

    private final DtoMapper mapper = mock(DtoMapper.class);
    private final EntityUtilityService utils = mock(EntityUtilityService.class);
    private final GroupRoleServiceImpl service = new GroupRoleServiceImpl(mapper, utils);

    private static Role role(String name) {
        Role role = new Role();
        role.setRoleName(name);
        return role;
    }

    private static PermissionGroup group(String name) {
        PermissionGroup group = new PermissionGroup();
        group.setGroupName(name);
        return group;
    }

    @Test
    void assignRoleToGroup_nullGroupOrRole_throwsEmptyField() {
        assertThatThrownBy(() -> service.assignRoleToGroup(null, "buyer"))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.EMPTY_FIELD));
        assertThatThrownBy(() -> service.assignRoleToGroup("buyers", null))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.EMPTY_FIELD));
        verifyNoInteractions(utils, mapper);
    }

    @Test
    void assignRoleToGroup_currentBehavior_blankStringIsNotTreatedAsEmpty() {
        when(utils.getRole("  ")).thenReturn(role("  "));
        when(utils.getPermissionGroup(" ")).thenReturn(group(" "));
        when(utils.isRoleAndPermissionGroupMappingExisting(any(), any())).thenReturn(false);
        when(utils.saveRolePermissionGroupMapping(any())).thenReturn(new RolePermissionGroupMapping());

        assertThatCode(() -> service.assignRoleToGroup(" ", "  ")).doesNotThrowAnyException();
    }

    @Test
    void assignRoleToGroup_success_savesMappingAndReturnsMappedResponse() {
        Role role = role("buyer");
        PermissionGroup group = group("buyers");
        RolePermissionGroupMapping saved = new RolePermissionGroupMapping();
        RoleAndPermissionGroupMappingResponse expected = new RoleAndPermissionGroupMappingResponse();

        when(utils.getRole("buyer")).thenReturn(role);
        when(utils.getPermissionGroup("buyers")).thenReturn(group);
        when(utils.isRoleAndPermissionGroupMappingExisting(role, group)).thenReturn(false);
        when(utils.saveRolePermissionGroupMapping(any())).thenReturn(saved);
        when(mapper.buildRoleAndPermissionGroupMappingResponse(saved)).thenReturn(expected);

        RoleAndPermissionGroupMappingResponse result = service.assignRoleToGroup("buyers", "buyer");

        assertThat(result).isSameAs(expected);
    }

    @Test
    void assignRoleToGroup_alreadyMapped_throwsAlreadyExistsAndNeverSaves() {
        Role role = role("buyer");
        PermissionGroup group = group("buyers");
        when(utils.getRole("buyer")).thenReturn(role);
        when(utils.getPermissionGroup("buyers")).thenReturn(group);
        when(utils.isRoleAndPermissionGroupMappingExisting(role, group)).thenReturn(true);

        assertThatThrownBy(() -> service.assignRoleToGroup("buyers", "buyer"))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.ALREADY_EXISTS));
        verify(utils, never()).saveRolePermissionGroupMapping(any());
    }

    @Test
    void assignRoleToGroup_currentBehavior_roleNotFoundIsRemappedToRoleNotFound() {
        when(utils.getRole("buyer")).thenThrow(PermissionException.roleNotFound("no such role"));

        assertThatThrownBy(() -> service.assignRoleToGroup("buyers", "buyer"))
                .isInstanceOfSatisfying(PermissionException.class, ex -> {
                    assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.ROLE_NOT_FOUND);
                    assertThat(ex.getMessage()).contains("Role or permission group not found");
                });
    }

    @Test
    void assignRoleToGroup_currentBehavior_permissionGroupNotFoundIsAlsoRemappedToRoleNotFound() {
        when(utils.getRole("buyer")).thenReturn(role("buyer"));
        when(utils.getPermissionGroup("buyers")).thenThrow(PermissionException.permissionGroupNotFound("no such group"));

        assertThatThrownBy(() -> service.assignRoleToGroup("buyers", "buyer"))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.ROLE_NOT_FOUND));
    }

    @Test
    void assignRoleToGroup_otherPermissionException_isRethrownUnchanged() {
        PermissionException other = PermissionException.operationFailed("weird failure");
        when(utils.getRole("buyer")).thenThrow(other);

        assertThatThrownBy(() -> service.assignRoleToGroup("buyers", "buyer")).isSameAs(other);
    }

    @Test
    void assignRoleToGroup_dataAccessExceptionOnSave_isWrappedAsGroupRoleMappingFailed() {
        Role role = role("buyer");
        PermissionGroup group = group("buyers");
        when(utils.getRole("buyer")).thenReturn(role);
        when(utils.getPermissionGroup("buyers")).thenReturn(group);
        when(utils.isRoleAndPermissionGroupMappingExisting(role, group)).thenReturn(false);
        when(utils.saveRolePermissionGroupMapping(any())).thenThrow(new DataAccessException("db down") {
        });

        assertThatThrownBy(() -> service.assignRoleToGroup("buyers", "buyer"))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.GROUP_ROLE_MAPPING_FAILED));
    }

    @Test
    void assignRoleToSubGroup_nullGroupOrRole_throwsEmptyField() {
        assertThatThrownBy(() -> service.assignRoleToSubGroup(null, "buyer"))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.EMPTY_FIELD));
        verifyNoInteractions(utils, mapper);
    }

    @Test
    void assignRoleToSubGroup_success_savesMappingAndReturnsMappedResponse() {
        RolePermissionGroupMapping saved = new RolePermissionGroupMapping();
        RoleAndPermissionGroupMappingResponse expected = new RoleAndPermissionGroupMappingResponse();

        when(utils.getRole("buyer")).thenReturn(role("buyer"));
        when(utils.getSubPermissionGroupByName("tier1")).thenReturn(new com.internal.auth.feature.rbac.model.SubPermissionGroup());
        when(utils.saveRolePermissionGroupMapping(any())).thenReturn(saved);
        when(mapper.buildRoleAndPermissionGroupMappingResponse(saved)).thenReturn(expected);

        RoleAndPermissionGroupMappingResponse result = service.assignRoleToSubGroup("tier1", "buyer");

        assertThat(result).isSameAs(expected);
    }

    @Test
    void assignRoleToSubGroup_currentBehavior_hasNoAlreadyAssignedGuardUnlikeAssignRoleToGroup() {
        when(utils.getRole("buyer")).thenReturn(role("buyer"));
        when(utils.getSubPermissionGroupByName("tier1")).thenReturn(new com.internal.auth.feature.rbac.model.SubPermissionGroup());
        when(utils.saveRolePermissionGroupMapping(any())).thenReturn(new RolePermissionGroupMapping());

        assertThatCode(() -> {
            service.assignRoleToSubGroup("tier1", "buyer");
            service.assignRoleToSubGroup("tier1", "buyer");
        }).doesNotThrowAnyException();
    }

    @Test
    void assignRoleToSubGroup_currentBehavior_permissionExceptionFromLookupIsNotCaughtOrRemapped() {
        PermissionException notFound = PermissionException.subGroupNotFound("no such subgroup");
        when(utils.getRole("buyer")).thenReturn(role("buyer"));
        when(utils.getSubPermissionGroupByName("tier1")).thenThrow(notFound);

        assertThatThrownBy(() -> service.assignRoleToSubGroup("tier1", "buyer")).isSameAs(notFound);
    }

    @Test
    void assignRoleToSubGroup_dataAccessExceptionOnSave_isWrappedAsGroupRoleMappingFailed() {
        when(utils.getRole("buyer")).thenReturn(role("buyer"));
        when(utils.getSubPermissionGroupByName("tier1")).thenReturn(new com.internal.auth.feature.rbac.model.SubPermissionGroup());
        when(utils.saveRolePermissionGroupMapping(any())).thenThrow(new DataAccessException("db down") {
        });

        assertThatThrownBy(() -> service.assignRoleToSubGroup("tier1", "buyer"))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.GROUP_ROLE_MAPPING_FAILED));
    }
}
