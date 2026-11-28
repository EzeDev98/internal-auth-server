package com.internal.auth.feature.rbac.service.impl;

import com.internal.auth.common.exception.PermissionErrorCode;
import com.internal.auth.common.exception.PermissionException;
import com.internal.auth.common.response.BaseResponse;
import com.internal.auth.feature.rbac.response.*;
import com.internal.auth.feature.rbac.service.*;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Unit tests for PermissionManagementServiceImpl. */
class PermissionManagementServiceImplTest {

    private final PermissionEntityService permissionEntityService = mock(PermissionEntityService.class);
    private final UserRoleService userRoleService = mock(UserRoleService.class);
    private final GroupRoleService groupRoleService = mock(GroupRoleService.class);
    private final UserPermissionGroupService groupService = mock(UserPermissionGroupService.class);

    private final PermissionManagementServiceImpl service = new PermissionManagementServiceImpl(
            permissionEntityService, userRoleService, groupRoleService, groupService);

    @Test
    void createRole_blankRoleName_throwsWithoutCallingCollaborator() {
        assertThatThrownBy(() -> service.createRole("  ", "desc"))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.EMPTY_FIELD));
        verifyNoInteractions(permissionEntityService);
    }

    @Test
    void createRole_normalizesCaseAndWhitespaceBeforeDelegating() {
        RoleResponse roleResponse = new RoleResponse();
        when(permissionEntityService.createRole("buyer", "desc")).thenReturn(roleResponse);

        BaseResponse response = service.createRole("  BUYER  ", "desc");

        verify(permissionEntityService).createRole("buyer", "desc");
        assertThat(response.getStatusCode()).isEqualTo(201);
        assertThat(response.getDescription()).isEqualTo("Role created successfully");
        assertThat(response.getData()).isSameAs(roleResponse);
    }

    @Test
    void createRole_permissionExceptionFromCollaborator_isRethrownAsIs() {
        PermissionException original = PermissionException.alreadyExists("role exists");
        when(permissionEntityService.createRole("buyer", "desc")).thenThrow(original);

        assertThatThrownBy(() -> service.createRole("buyer", "desc")).isSameAs(original);
    }

    @Test
    void createRole_unexpectedExceptionFromCollaborator_isWrappedAsInternalError() {
        when(permissionEntityService.createRole("buyer", "desc")).thenThrow(new IllegalStateException("db down"));

        assertThatThrownBy(() -> service.createRole("buyer", "desc"))
                .isInstanceOfSatisfying(PermissionException.class, ex -> {
                    assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.INTERNAL_ERROR);
                    assertThat(ex.getMessage()).contains("db down");
                });
    }

    @Test
    void createSuperGroup_blankGroupName_throws() {
        assertThatThrownBy(() -> service.createSuperGroup(" ", "desc"))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.EMPTY_FIELD));
        verifyNoInteractions(permissionEntityService);
    }

    @Test
    void createSuperGroup_normalizesAndDelegates() {
        GroupCreationResponse groupResponse = new GroupCreationResponse();
        when(permissionEntityService.createSuperGroup("buyers", "desc")).thenReturn(groupResponse);

        BaseResponse response = service.createSuperGroup("  BUYERS  ", "desc");

        verify(permissionEntityService).createSuperGroup("buyers", "desc");
        assertThat(response.getStatusCode()).isEqualTo(201);
        assertThat(response.getData()).isSameAs(groupResponse);
    }

    @Test
    void createSubGroup_blankGroupNameOrParent_throws() {
        assertThatThrownBy(() -> service.createSubGroup(" ", "desc", "parent"))
                .isInstanceOf(PermissionException.class);
        assertThatThrownBy(() -> service.createSubGroup("group", "desc", " "))
                .isInstanceOf(PermissionException.class);
        verifyNoInteractions(permissionEntityService);
    }

    @Test
    void createSubGroup_normalizesBothNamesAndDelegates() {
        SubGroupCreationResponse subGroupResponse = new SubGroupCreationResponse();
        when(permissionEntityService.createSubGroup("tier1", "desc", "buyers")).thenReturn(subGroupResponse);

        BaseResponse response = service.createSubGroup("  TIER1  ", "desc", "  BUYERS  ");

        verify(permissionEntityService).createSubGroup("tier1", "desc", "buyers");
        assertThat(response.getStatusCode()).isEqualTo(201);
        assertThat(response.getData()).isSameAs(subGroupResponse);
    }

    @Test
    void assignRoleToUser_blankUsernameOrRole_throws() {
        assertThatThrownBy(() -> service.assignRoleToUser(" ", "buyer")).isInstanceOf(PermissionException.class);
        assertThatThrownBy(() -> service.assignRoleToUser("user1", " ")).isInstanceOf(PermissionException.class);
        verifyNoInteractions(userRoleService);
    }

    @Test
    void assignRoleToUser_normalizesRoleCaseButNotUsernameCase() {
        UserRoleResponse roleResponse = new UserRoleResponse();
        when(userRoleService.assignRole("User1", "buyer")).thenReturn(roleResponse);

        BaseResponse response = service.assignRoleToUser("User1", "  BUYER  ");

        verify(userRoleService).assignRole("User1", "buyer");
        assertThat(response.getStatusCode()).isEqualTo(201);
        assertThat(response.getData()).isSameAs(roleResponse);
    }

    @Test
    void assignRoleToGroup_blankGroupOrRole_throws() {
        assertThatThrownBy(() -> service.assignRoleToGroup(" ", "buyer")).isInstanceOf(PermissionException.class);
        verifyNoInteractions(groupRoleService);
    }

    @Test
    void assignRoleToGroup_success_normalizesAndDelegates() {
        RoleAndPermissionGroupMappingResponse mappingResponse = new RoleAndPermissionGroupMappingResponse();
        when(groupRoleService.assignRoleToGroup("buyers", "buyer")).thenReturn(mappingResponse);

        BaseResponse response = service.assignRoleToGroup("  BUYERS  ", "  BUYER  ");

        verify(groupRoleService).assignRoleToGroup("buyers", "buyer");
        assertThat(response.getStatusCode()).isEqualTo(201);
        assertThat(response.getDescription()).isEqualTo("Role assigned to group successfully");
    }

    @Test
    void assignRoleToGroup_alreadyAssigned_returnsOkNoOpInsteadOfThrowing() {
        when(groupRoleService.assignRoleToGroup("buyers", "buyer"))
                .thenThrow(PermissionException.alreadyExists("already there"));

        BaseResponse response = service.assignRoleToGroup("buyers", "buyer");

        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getDescription()).isEqualTo("Role already assigned to group");
        assertThat(response.getData()).isNull();
    }

    @Test
    void assignRoleToGroup_otherPermissionException_isRethrown() {
        PermissionException notFound = PermissionException.groupNotFound("no such group");
        when(groupRoleService.assignRoleToGroup("buyers", "buyer")).thenThrow(notFound);

        assertThatThrownBy(() -> service.assignRoleToGroup("buyers", "buyer")).isSameAs(notFound);
    }

    @Test
    void assignRoleToSubGroup_blankAnyField_throws() {
        assertThatThrownBy(() -> service.assignRoleToSubGroup(" ", "group", "role"))
                .isInstanceOf(PermissionException.class);
        assertThatThrownBy(() -> service.assignRoleToSubGroup("super", " ", "role"))
                .isInstanceOf(PermissionException.class);
        assertThatThrownBy(() -> service.assignRoleToSubGroup("super", "group", " "))
                .isInstanceOf(PermissionException.class);
        verifyNoInteractions(groupRoleService);
    }

    @Test
    void assignRoleToSubGroup_currentBehavior_superGroupNameValidatedButNeverForwarded() {
        RoleAndPermissionGroupMappingResponse mappingResponse = new RoleAndPermissionGroupMappingResponse();
        when(groupRoleService.assignRoleToSubGroup("tier1", "buyer")).thenReturn(mappingResponse);

        BaseResponse response = service.assignRoleToSubGroup("ANY-SUPERGROUP-VALUE", "  TIER1  ", "  BUYER  ");

        verify(groupRoleService).assignRoleToSubGroup("tier1", "buyer");
        assertThat(response.getStatusCode()).isEqualTo(201);
    }

    @Test
    void addUserToGroup_blankUsernameOrGroup_throws() {
        assertThatThrownBy(() -> service.addUserToGroup(" ", "group")).isInstanceOf(PermissionException.class);
        verifyNoInteractions(groupService);
    }

    @Test
    void addUserToGroup_normalizesBothAndDelegates() {
        UserPermissionGroupResponse groupResponse = new UserPermissionGroupResponse();
        when(groupService.addUserToGroup("user1", "buyers")).thenReturn(groupResponse);

        BaseResponse response = service.addUserToGroup("  USER1  ", "  BUYERS  ");

        verify(groupService).addUserToGroup("user1", "buyers");
        assertThat(response.getStatusCode()).isEqualTo(201);
        assertThat(response.getData()).isSameAs(groupResponse);
    }

    @Test
    void addUserToSubGroup_blankAnyField_throws() {
        assertThatThrownBy(() -> service.addUserToSubGroup(" ", "super", "sub"))
                .isInstanceOf(PermissionException.class);
        assertThatThrownBy(() -> service.addUserToSubGroup("user", " ", "sub"))
                .isInstanceOf(PermissionException.class);
        assertThatThrownBy(() -> service.addUserToSubGroup("user", "super", " "))
                .isInstanceOf(PermissionException.class);
        verifyNoInteractions(groupService);
    }

    @Test
    void addUserToSubGroup_normalizesAllThreeAndDelegates() {
        UserSubPermissionGroupResponse subGroupResponse = new UserSubPermissionGroupResponse();
        when(groupService.addUserToSubGroup("user1", "buyers", "tier1")).thenReturn(subGroupResponse);

        BaseResponse response = service.addUserToSubGroup("  USER1  ", "  BUYERS  ", "  TIER1  ");

        verify(groupService).addUserToSubGroup("user1", "buyers", "tier1");
        assertThat(response.getStatusCode()).isEqualTo(201);
        assertThat(response.getData()).isSameAs(subGroupResponse);
    }

    @Test
    void addUserToSubGroups_blankUsernameOrSuperGroup_throws() {
        assertThatThrownBy(() -> service.addUserToSubGroups(" ", "super", List.of("tier1")))
                .isInstanceOf(PermissionException.class);
        verifyNoInteractions(groupService);
    }

    @Test
    void addUserToSubGroups_nullOrEmptySubGroupNames_throwsEmptyRequest() {
        assertThatThrownBy(() -> service.addUserToSubGroups("user1", "super", null))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.EMPTY_REQUEST));
        assertThatThrownBy(() -> service.addUserToSubGroups("user1", "super", List.of()))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.EMPTY_REQUEST));
    }

    @Test
    void addUserToSubGroups_normalizesAndFiltersSubGroupNameList() {
        when(groupService.addUserToSubGroups("user1", "buyers", List.of("tier1", "tier2")))
                .thenReturn(List.of(new UserPermissionGroupResponse()));

        BaseResponse response = service.addUserToSubGroups(
                "  USER1  ", "  BUYERS  ", Arrays.asList("  TIER1 ", null, " ", "TIER2"));

        verify(groupService).addUserToSubGroups("user1", "buyers", List.of("tier1", "tier2"));
        assertThat(response.getStatusCode()).isEqualTo(201);
    }

    @Test
    void unassignRole_blankUsernameOrRole_throws() {
        assertThatThrownBy(() -> service.unassignRole(" ", "buyer")).isInstanceOf(PermissionException.class);
        verifyNoInteractions(userRoleService);
    }

    @Test
    void unassignRole_normalizesAndBuildsMapResponse() {
        RemoveRoleResponse removeResponse = new RemoveRoleResponse(200, "Role unassigned", "buyer", "user1");
        when(userRoleService.unassignRole("user1", "buyer")).thenReturn(removeResponse);

        BaseResponse response = service.unassignRole("  USER1  ", "  BUYER  ");

        verify(userRoleService).unassignRole("user1", "buyer");
        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getDescription()).isEqualTo("Role unassigned");
        assertThat(response.getData()).usingRecursiveComparison().isEqualTo(new UnassignRoleResult("user1", "buyer"));
    }

    @Test
    void unassignRole_permissionExceptionFromCollaborator_isRethrown() {
        PermissionException notAssigned = PermissionException.roleNotAssigned("not assigned");
        when(userRoleService.unassignRole("user1", "buyer")).thenThrow(notAssigned);

        assertThatThrownBy(() -> service.unassignRole("user1", "buyer")).isSameAs(notAssigned);
    }

    @Test
    void unassignRole_unexpectedException_isWrappedAsInternalError() {
        when(userRoleService.unassignRole("user1", "buyer")).thenThrow(new IllegalStateException("db timeout"));

        assertThatThrownBy(() -> service.unassignRole("user1", "buyer"))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.INTERNAL_ERROR));
    }

    @Test
    void removeUserFromGroup_blankUsernameOrGroup_throws() {
        assertThatThrownBy(() -> service.removeUserFromGroup(" ", "group")).isInstanceOf(PermissionException.class);
        verifyNoInteractions(groupService);
    }

    @Test
    void removeUserFromGroup_currentBehavior_responseMapKeyIsMisleadinglyNamedRoleName() {
        RemoveUserResponse removeResponse = new RemoveUserResponse(200, "User removed", "user1", "buyers");
        when(groupService.removeUserFromPermissionGroup("user1", "buyers")).thenReturn(removeResponse);

        BaseResponse response = service.removeUserFromGroup("  USER1  ", "  BUYERS  ");

        verify(groupService).removeUserFromPermissionGroup("user1", "buyers");
        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getData()).usingRecursiveComparison().isEqualTo(new RemoveUserFromGroupResult("user1", "buyers"));
    }

    @Test
    void deleteSuperGroup_blankGroupName_throws() {
        assertThatThrownBy(() -> service.deleteSuperGroup(" ")).isInstanceOf(PermissionException.class);
        verifyNoInteractions(permissionEntityService);
    }

    @Test
    void deleteSuperGroup_normalizesAndDelegates() {
        BaseResponse response = service.deleteSuperGroup("  BUYERS  ");

        verify(permissionEntityService).deleteSuperGroup("buyers");
        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getDescription()).isEqualTo("Group deleted successfully: buyers");
    }

    @Test
    void deleteSuperGroup_permissionExceptionFromCollaborator_isRethrown() {
        PermissionException notFound = PermissionException.groupNotFound("no such group");
        doThrow(notFound).when(permissionEntityService).deleteSuperGroup("buyers");

        assertThatThrownBy(() -> service.deleteSuperGroup("buyers")).isSameAs(notFound);
    }
}
