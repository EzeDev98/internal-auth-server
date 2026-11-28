package com.internal.auth.feature.rbac.service.impl;

import com.internal.auth.common.exception.PermissionErrorCode;
import com.internal.auth.common.exception.PermissionException;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.rbac.model.Role;
import com.internal.auth.feature.rbac.model.UserRole;
import com.internal.auth.feature.rbac.response.BulkRoleAssignmentResponse;
import com.internal.auth.feature.rbac.response.RemoveRoleResponse;
import com.internal.auth.feature.rbac.response.UserRoleResponse;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessException;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Unit tests for UserRoleServiceImpl. */
class UserRoleServiceImplTest {

    private final DtoMapper mapper = mock(DtoMapper.class);
    private final EntityUtilityService utils = mock(EntityUtilityService.class);
    private final UserRoleServiceImpl service = new UserRoleServiceImpl(mapper, utils);

    private static User user(String username) {
        User user = new User();
        user.setUsername(username);
        return user;
    }

    private static Role role(String name) {
        Role role = new Role();
        role.setRoleName(name);
        return role;
    }

    @Test
    void assignRole_nullUsernameOrRole_throwsEmptyField() {
        assertThatThrownBy(() -> service.assignRole(null, "buyer"))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.EMPTY_FIELD));
        verifyNoInteractions(utils);
    }

    @Test
    void assignRole_currentBehavior_blankStringIsNotTreatedAsEmpty() {
        when(utils.userRoleExists("  ", " ")).thenReturn(false);
        when(utils.getUser("  ")).thenReturn(user("  "));
        when(utils.getRole(" ")).thenReturn(role(" "));
        when(utils.saveUserRole(any())).thenReturn(new UserRole());

        assertThatCode(() -> service.assignRole("  ", " ")).doesNotThrowAnyException();
    }

    @Test
    void assignRole_alreadyAssigned_throwsDuplicateRoleAssignment() {
        when(utils.userRoleExists("user1", "buyer")).thenReturn(true);

        assertThatThrownBy(() -> service.assignRole("user1", "buyer"))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.DUPLICATE_ROLE_ASSIGNMENT));
        verify(utils, never()).saveUserRole(any());
    }

    @Test
    void assignRole_success_savesAndReturnsMappedResponse() {
        UserRole saved = new UserRole();
        UserRoleResponse expected = new UserRoleResponse();
        when(utils.userRoleExists("user1", "buyer")).thenReturn(false);
        when(utils.getUser("user1")).thenReturn(user("user1"));
        when(utils.getRole("buyer")).thenReturn(role("buyer"));
        when(utils.saveUserRole(any())).thenReturn(saved);
        when(mapper.buildUserRole(saved)).thenReturn(expected);

        UserRoleResponse result = service.assignRole("user1", "buyer");

        assertThat(result).isSameAs(expected);
    }

    @Test
    void assignRole_currentBehavior_permissionExceptionFromLookupIsNotCaughtOrRemapped() {
        PermissionException notFound = PermissionException.userNotFound("no such user");
        when(utils.userRoleExists("user1", "buyer")).thenReturn(false);
        when(utils.getUser("user1")).thenThrow(notFound);

        assertThatThrownBy(() -> service.assignRole("user1", "buyer")).isSameAs(notFound);
    }

    @Test
    void assignRole_dataAccessExceptionOnSave_isWrappedAsUserRolePersistenceFailed() {
        when(utils.userRoleExists("user1", "buyer")).thenReturn(false);
        when(utils.getUser("user1")).thenReturn(user("user1"));
        when(utils.getRole("buyer")).thenReturn(role("buyer"));
        when(utils.saveUserRole(any())).thenThrow(new DataAccessException("db down") {
        });

        assertThatThrownBy(() -> service.assignRole("user1", "buyer"))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.USER_ROLE_PERSISTENCE_FAILED));
    }

    @Test
    void unassignRole_blankUsernameOrRole_throwsEmptyField() {
        assertThatThrownBy(() -> service.unassignRole(" ", "buyer"))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.EMPTY_FIELD));
        verifyNoInteractions(utils);
    }

    @Test
    void unassignRole_success_currentBehavior_usernameAndRoleNameAreSwappedInResponse() {
        User user = user("user1");
        Role role = role("buyer");
        UserRole mapping = new UserRole();
        when(utils.getUser("user1")).thenReturn(user);
        when(utils.getRole("buyer")).thenReturn(role);
        when(utils.getUserAndRole(user, role)).thenReturn(mapping);

        RemoveRoleResponse response = service.unassignRole("user1", "buyer");

        verify(utils).deleteUserAndRoleMapping(mapping);
        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getRoleName()).isEqualTo("user1");
        assertThat(response.getUsername()).isEqualTo("buyer");
        assertThat(response.getMessage()).contains("successfully removed");
    }

    @Test
    void unassignRole_currentBehavior_mappingNullReturnsNothingToRemoveInsteadOfDeleting() {
        User user = user("user1");
        Role role = role("buyer");
        when(utils.getUser("user1")).thenReturn(user);
        when(utils.getRole("buyer")).thenReturn(role);
        when(utils.getUserAndRole(user, role)).thenReturn(null);

        RemoveRoleResponse response = service.unassignRole("user1", "buyer");

        verify(utils, never()).deleteUserAndRoleMapping(any());
        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getMessage()).contains("nothing to remove");
    }

    @Test
    void unassignRole_currentBehavior_notFoundFromLookupIsWrappedAsGenericOperationFailed() {
        when(utils.getUser("user1")).thenThrow(PermissionException.userNotFound("no such user"));

        assertThatThrownBy(() -> service.unassignRole("user1", "buyer"))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.PERMISSION_OPERATION_FAILED));
    }

    @Test
    void assignRoles_nullUsername_throwsEmptyField() {
        assertThatThrownBy(() -> service.assignRoles(null, List.of("buyer")))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.EMPTY_FIELD));
    }

    @Test
    void assignRoles_nullOrEmptyRoles_throwsEmptyField() {
        assertThatThrownBy(() -> service.assignRoles("user1", null))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.EMPTY_FIELD));
        assertThatThrownBy(() -> service.assignRoles("user1", List.of()))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.EMPTY_FIELD));
    }

    @Test
    void assignRoles_someRoleDoesNotExist_throwsBeforeAssigningAnything() {
        when(utils.isRoleExist("buyer")).thenReturn(true);
        when(utils.isRoleExist("ghost")).thenReturn(false);

        assertThatThrownBy(() -> service.assignRoles("user1", List.of("buyer", "ghost")))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.ROLE_NOT_FOUND));
        verify(utils, never()).saveUserRole(any());
    }

    @Test
    void assignRoles_deduplicatesRolesBeforeAssigning() {
        when(utils.isRoleExist(anyString())).thenReturn(true);
        when(utils.userRoleExists(anyString(), anyString())).thenReturn(false);
        when(utils.getUser(anyString())).thenReturn(user("user1"));
        when(utils.getRole(anyString())).thenReturn(role("buyer"));
        when(utils.saveUserRole(any())).thenReturn(new UserRole());

        service.assignRoles("user1", List.of("buyer", "buyer", "seller"));

        verify(utils, times(2)).saveUserRole(any());
    }

    @Test
    void assignRoles_currentBehavior_aSingleAlreadyAssignedRoleAbortsTheWholeCall() {
        when(utils.isRoleExist("buyer")).thenReturn(true);
        when(utils.userRoleExists("user1", "buyer")).thenReturn(true);

        assertThatThrownBy(() -> service.assignRoles("user1", List.of("buyer")))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.DUPLICATE_ROLE_ASSIGNMENT));
    }

    @Test
    void bulkRoleAssignment_nullOrEmptyUsernames_throwsEmptyField() {
        assertThatThrownBy(() -> service.bulkRoleAssignment(null, List.of("buyer")))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.EMPTY_FIELD));
        assertThatThrownBy(() -> service.bulkRoleAssignment(List.of(), List.of("buyer")))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.EMPTY_FIELD));
    }

    @Test
    void bulkRoleAssignment_nullOrEmptyRoles_throwsEmptyField() {
        assertThatThrownBy(() -> service.bulkRoleAssignment(List.of("user1"), null))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.EMPTY_FIELD));
        assertThatThrownBy(() -> service.bulkRoleAssignment(List.of("user1"), List.of()))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.EMPTY_FIELD));
    }

    @Test
    void bulkRoleAssignment_blankPair_isCollectedAsFailureNotAttempted() {
        BulkRoleAssignmentResponse response = service.bulkRoleAssignment(List.of(" "), List.of("buyer"));

        assertThat(response.getFailed()).isEqualTo(1);
        assertThat(response.getFailures().get(0)).contains("[blank field]");
        verifyNoInteractions(utils);
    }

    @Test
    void bulkRoleAssignment_existingPair_isCollectedAsDuplicateNotThrown() {
        when(utils.userRoleExists("user1", "buyer")).thenReturn(true);

        BulkRoleAssignmentResponse response = service.bulkRoleAssignment(List.of("user1"), List.of("buyer"));

        assertThat(response.getSkippedDuplicates()).isEqualTo(1);
        assertThat(response.getSuccessfullyAssigned()).isEqualTo(0);
        assertThat(response.getTotalRequested()).isEqualTo(1);
        verify(utils, never()).saveAllUserRoles(any());
    }

    @Test
    void bulkRoleAssignment_currentBehavior_perPairExceptionIsCollectedNotThrown() {
        when(utils.userRoleExists("user1", "buyer")).thenReturn(false);
        when(utils.getUser("user1")).thenThrow(PermissionException.userNotFound("no such user"));

        BulkRoleAssignmentResponse response = service.bulkRoleAssignment(List.of("user1"), List.of("buyer"));

        assertThat(response.getFailed()).isEqualTo(1);
        assertThat(response.getSuccessfullyAssigned()).isEqualTo(0);
    }

    @Test
    void bulkRoleAssignment_success_savesAndReturnsMappedResponses() {
        UserRole toSave = new UserRole();
        UserRoleResponse mapped = new UserRoleResponse();
        when(utils.userRoleExists("user1", "buyer")).thenReturn(false);
        when(utils.getUser("user1")).thenReturn(user("user1"));
        when(utils.getRole("buyer")).thenReturn(role("buyer"));
        when(utils.saveAllUserRoles(any())).thenReturn(List.of(toSave));
        when(mapper.buildUserRole(toSave)).thenReturn(mapped);

        BulkRoleAssignmentResponse response = service.bulkRoleAssignment(List.of("user1"), List.of("buyer"));

        assertThat(response.getSuccessfullyAssigned()).isEqualTo(1);
        assertThat(response.getAssigned()).containsExactly(mapped);
    }

    @Test
    void bulkRoleAssignment_dataAccessExceptionOnSave_isWrappedAsUserRolePersistenceFailed() {
        when(utils.userRoleExists("user1", "buyer")).thenReturn(false);
        when(utils.getUser("user1")).thenReturn(user("user1"));
        when(utils.getRole("buyer")).thenReturn(role("buyer"));
        when(utils.saveAllUserRoles(any())).thenThrow(new DataAccessException("db down") {
        });

        assertThatThrownBy(() -> service.bulkRoleAssignment(List.of("user1"), List.of("buyer")))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.USER_ROLE_PERSISTENCE_FAILED));
    }

    @Test
    void bulkRoleAssignment_totalRequestedIsTheFullCrossProduct() {
        when(utils.userRoleExists(anyString(), anyString())).thenReturn(true);

        BulkRoleAssignmentResponse response = service.bulkRoleAssignment(
                List.of("user1", "user2"), List.of("buyer", "seller", "viewer"));

        assertThat(response.getTotalRequested()).isEqualTo(6);
        assertThat(response.getSkippedDuplicates()).isEqualTo(6);
    }
}
