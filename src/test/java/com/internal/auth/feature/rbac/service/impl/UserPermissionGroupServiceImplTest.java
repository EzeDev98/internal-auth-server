package com.internal.auth.feature.rbac.service.impl;

import com.internal.auth.common.exception.PermissionErrorCode;
import com.internal.auth.common.exception.PermissionException;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.rbac.model.PermissionGroup;
import com.internal.auth.feature.rbac.model.Role;
import com.internal.auth.feature.rbac.model.UserPermissionGroup;
import com.internal.auth.feature.rbac.response.RemoveUserResponse;
import com.internal.auth.feature.rbac.response.UserPermissionGroupResponse;
import com.internal.auth.feature.rbac.response.UserSubPermissionGroupResponse;
import com.internal.auth.feature.rbac.service.UserRoleService;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessException;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class UserPermissionGroupServiceImplTest {

    private final EntityUtilityService utils = mock(EntityUtilityService.class);
    private final DtoMapper mapper = mock(DtoMapper.class);
    private final UserRoleService roleService = mock(UserRoleService.class);
    private final UserPermissionGroupServiceImpl service =
            new UserPermissionGroupServiceImpl(utils, mapper, roleService);

    private static User user(String username) {
        User user = new User();
        user.setUsername(username);
        return user;
    }

    private static PermissionGroup group(String name) {
        PermissionGroup group = new PermissionGroup();
        group.setGroupName(name);
        return group;
    }

    private static Role role(String name) {
        Role role = new Role();
        role.setRoleName(name);
        return role;
    }

    // -- removeUserFromPermissionGroup ---------------------------------------

    @Test
    void removeUserFromPermissionGroup_blankUsernameOrGroup_throws() {
        assertThatThrownBy(() -> service.removeUserFromPermissionGroup(" ", "group"))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.EMPTY_FIELD));
        verifyNoInteractions(utils, roleService);
    }

    @Test
    void removeUserFromPermissionGroup_success_unassignsEachGroupRoleAndDeletesMapping() {
        User user = user("user1");
        PermissionGroup group = group("buyers");
        UserPermissionGroup mapping = new UserPermissionGroup();
        when(utils.getUser("user1")).thenReturn(user);
        when(utils.getPermissionGroup("buyers")).thenReturn(group);
        when(utils.getUserAndGroup(user, group)).thenReturn(mapping);
        when(utils.getGroupRoles(group)).thenReturn(List.of(role("buyer"), role("viewer")));

        RemoveUserResponse response = service.removeUserFromPermissionGroup("user1", "buyers");

        verify(roleService).unassignRole("user1", "buyer");
        verify(roleService).unassignRole("user1", "viewer");
        verify(utils).deleteUserAndGroupMapping(mapping);
        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getUsername()).isEqualTo("user1");
        assertThat(response.getGroupName()).isEqualTo("buyers");
    }

    @Test
    void removeUserFromPermissionGroup_currentBehavior_perRoleUnassignFailureIsSwallowed() {
        // A role that fails to unassign is logged and skipped - it does not
        // abort removing the user from the group.
        User user = user("user1");
        PermissionGroup group = group("buyers");
        UserPermissionGroup mapping = new UserPermissionGroup();
        when(utils.getUser("user1")).thenReturn(user);
        when(utils.getPermissionGroup("buyers")).thenReturn(group);
        when(utils.getUserAndGroup(user, group)).thenReturn(mapping);
        when(utils.getGroupRoles(group)).thenReturn(List.of(role("buyer")));
        when(roleService.unassignRole("user1", "buyer")).thenThrow(new RuntimeException("boom"));

        RemoveUserResponse response = service.removeUserFromPermissionGroup("user1", "buyers");

        verify(utils).deleteUserAndGroupMapping(mapping);
        assertThat(response.getStatusCode()).isEqualTo(200);
    }

    @Test
    void removeUserFromPermissionGroup_permissionExceptionFromLookup_isRethrown() {
        PermissionException notFound = PermissionException.userNotFound("no such user");
        when(utils.getUser("user1")).thenThrow(notFound);

        assertThatThrownBy(() -> service.removeUserFromPermissionGroup("user1", "buyers")).isSameAs(notFound);
    }

    @Test
    void removeUserFromPermissionGroup_currentBehavior_unexpectedExceptionWrappedWithFixedMessage() {
        // The wrapping message here is a fixed string, not one that embeds
        // the underlying exception's message (unlike most other RBAC
        // catch-alls in this codebase).
        User user = user("user1");
        PermissionGroup group = group("buyers");
        when(utils.getUser("user1")).thenReturn(user);
        when(utils.getPermissionGroup("buyers")).thenReturn(group);
        when(utils.getUserAndGroup(user, group)).thenReturn(new UserPermissionGroup());
        when(utils.getGroupRoles(group)).thenThrow(new RuntimeException("db exploded"));

        assertThatThrownBy(() -> service.removeUserFromPermissionGroup("user1", "buyers"))
                .isInstanceOfSatisfying(PermissionException.class, ex -> {
                    assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.PERMISSION_OPERATION_FAILED);
                    assertThat(ex.getMessage()).isEqualTo("Failed to remove user from the specified group");
                });
    }

    // -- addUserToGroup (idempotency) ----------------------------------------

    @Test
    void addUserToGroup_nullUsernameOrGroup_throwsEmptyField() {
        assertThatThrownBy(() -> service.addUserToGroup(null, "buyers"))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.EMPTY_FIELD));
        verifyNoInteractions(utils);
    }

    @Test
    void addUserToGroup_groupHasNoRolesMapped_throwsOperationFailed() {
        PermissionGroup group = group("buyers");
        when(utils.getPermissionGroup("buyers")).thenReturn(group);
        when(utils.getGroupRoles(group)).thenReturn(List.of());

        assertThatThrownBy(() -> service.addUserToGroup("user1", "buyers"))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.PERMISSION_OPERATION_FAILED));
    }

    @Test
    void addUserToGroup_alreadyMember_returnsExistingMappingWithoutReassigningRoles() {
        PermissionGroup group = group("buyers");
        UserPermissionGroup existing = new UserPermissionGroup();
        UserPermissionGroupResponse expected = new UserPermissionGroupResponse();
        when(utils.getPermissionGroup("buyers")).thenReturn(group);
        when(utils.getGroupRoles(group)).thenReturn(List.of(role("buyer")));
        when(utils.userPermissionGroupExists("user1", "buyers")).thenReturn(true);
        when(utils.getUserPermissionGroup("user1", "buyers")).thenReturn(existing);
        when(mapper.buildUserPermissionGroup(existing)).thenReturn(expected);

        UserPermissionGroupResponse result = service.addUserToGroup("user1", "buyers");

        assertThat(result).isSameAs(expected);
        verify(utils, never()).saveUserPermissionGroup(any());
        verifyNoInteractions(roleService);
    }

    @Test
    void addUserToGroup_newMember_savesMappingAndAssignsEachGroupRole() {
        PermissionGroup group = group("buyers");
        User user = user("user1");
        UserPermissionGroup saved = new UserPermissionGroup();
        UserPermissionGroupResponse expected = new UserPermissionGroupResponse();
        when(utils.getPermissionGroup("buyers")).thenReturn(group);
        when(utils.getGroupRoles(group)).thenReturn(List.of(role("buyer"), role("viewer")));
        when(utils.userPermissionGroupExists("user1", "buyers")).thenReturn(false);
        when(utils.getUser("user1")).thenReturn(user);
        when(utils.saveUserPermissionGroup(any())).thenReturn(saved);
        when(mapper.buildUserPermissionGroup(saved)).thenReturn(expected);

        UserPermissionGroupResponse result = service.addUserToGroup("user1", "buyers");

        assertThat(result).isSameAs(expected);
        verify(roleService).assignRole("user1", "buyer");
        verify(roleService).assignRole("user1", "viewer");
    }

    @Test
    void addUserToGroup_currentBehavior_roleAssignmentFailureIsSwallowed() {
        PermissionGroup group = group("buyers");
        when(utils.getPermissionGroup("buyers")).thenReturn(group);
        when(utils.getGroupRoles(group)).thenReturn(List.of(role("buyer")));
        when(utils.userPermissionGroupExists("user1", "buyers")).thenReturn(false);
        when(utils.getUser("user1")).thenReturn(user("user1"));
        when(utils.saveUserPermissionGroup(any())).thenReturn(new UserPermissionGroup());
        when(roleService.assignRole(eq("user1"), anyString()))
                .thenThrow(PermissionException.duplicateRoleAssignment("already has it"));

        assertThatCode(() -> service.addUserToGroup("user1", "buyers")).doesNotThrowAnyException();
    }

    @Test
    void addUserToGroup_dataAccessExceptionOnSave_isWrappedAsUserGroupMappingFailed() {
        PermissionGroup group = group("buyers");
        when(utils.getPermissionGroup("buyers")).thenReturn(group);
        when(utils.getGroupRoles(group)).thenReturn(List.of(role("buyer")));
        when(utils.userPermissionGroupExists("user1", "buyers")).thenReturn(false);
        when(utils.getUser("user1")).thenReturn(user("user1"));
        when(utils.saveUserPermissionGroup(any())).thenThrow(new DataAccessException("db down") {
        });

        assertThatThrownBy(() -> service.addUserToGroup("user1", "buyers"))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.USER_GROUP_MAPPING_FAILED));
    }

    // -- addUserToSubGroup / addUserToSubGroups (no idempotency guard) ------

    @Test
    void addUserToSubGroup_success_savesAndReturnsMappedResponse() {
        UserPermissionGroup saved = new UserPermissionGroup();
        UserSubPermissionGroupResponse expected = new UserSubPermissionGroupResponse();
        when(utils.getUser("user1")).thenReturn(user("user1"));
        when(utils.getPermissionGroup("buyers")).thenReturn(group("buyers"));
        when(utils.getSubPermissionGroup("tier1")).thenReturn(new com.internal.auth.feature.rbac.model.SubPermissionGroup());
        when(utils.saveUserPermissionGroup(any())).thenReturn(saved);
        when(mapper.buildUserSubPermissionGroup(saved)).thenReturn(expected);

        UserSubPermissionGroupResponse result = service.addUserToSubGroup("user1", "buyers", "tier1");

        assertThat(result).isSameAs(expected);
    }

    @Test
    void addUserToSubGroup_currentBehavior_hasNoAlreadyMemberGuardUnlikeAddUserToGroup() {
        when(utils.getUser("user1")).thenReturn(user("user1"));
        when(utils.getPermissionGroup("buyers")).thenReturn(group("buyers"));
        when(utils.getSubPermissionGroup("tier1")).thenReturn(new com.internal.auth.feature.rbac.model.SubPermissionGroup());
        when(utils.saveUserPermissionGroup(any())).thenReturn(new UserPermissionGroup());

        assertThatCode(() -> {
            service.addUserToSubGroup("user1", "buyers", "tier1");
            service.addUserToSubGroup("user1", "buyers", "tier1");
        }).doesNotThrowAnyException();
    }

    @Test
    void addUserToSubGroup_dataAccessExceptionOnSave_isWrappedAsUserGroupMappingFailed() {
        when(utils.getUser("user1")).thenReturn(user("user1"));
        when(utils.getPermissionGroup("buyers")).thenReturn(group("buyers"));
        when(utils.getSubPermissionGroup("tier1")).thenReturn(new com.internal.auth.feature.rbac.model.SubPermissionGroup());
        when(utils.saveUserPermissionGroup(any())).thenThrow(new DataAccessException("db down") {
        });

        assertThatThrownBy(() -> service.addUserToSubGroup("user1", "buyers", "tier1"))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.USER_GROUP_MAPPING_FAILED));
    }

    @Test
    void addUserToSubGroups_success_savesAllAndReturnsMappedResponses() {
        List<UserPermissionGroup> saved = List.of(new UserPermissionGroup(), new UserPermissionGroup());
        List<UserPermissionGroupResponse> expected = List.of(new UserPermissionGroupResponse());
        when(utils.getUser("user1")).thenReturn(user("user1"));
        when(utils.getPermissionGroup("buyers")).thenReturn(group("buyers"));
        when(utils.getSubPermissionGroup(anyString())).thenReturn(new com.internal.auth.feature.rbac.model.SubPermissionGroup());
        when(utils.saveUserPermissionGroups(any())).thenReturn(saved);
        when(mapper.buildUserPermissionGroups(saved)).thenReturn(expected);

        List<UserPermissionGroupResponse> result =
                service.addUserToSubGroups("user1", "buyers", List.of("tier1", "tier2"));

        assertThat(result).isSameAs(expected);
    }

    @Test
    void addUserToSubGroups_dataAccessExceptionOnSave_isWrappedAsUserGroupMappingFailed() {
        when(utils.getUser("user1")).thenReturn(user("user1"));
        when(utils.getPermissionGroup("buyers")).thenReturn(group("buyers"));
        when(utils.getSubPermissionGroup(anyString())).thenReturn(new com.internal.auth.feature.rbac.model.SubPermissionGroup());
        when(utils.saveUserPermissionGroups(any())).thenThrow(new DataAccessException("db down") {
        });

        assertThatThrownBy(() -> service.addUserToSubGroups("user1", "buyers", List.of("tier1")))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.USER_GROUP_MAPPING_FAILED));
    }
}
