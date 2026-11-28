package com.internal.auth.common.exception;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Tag;

/** Unit tests for the deprecated permission exception subclasses. */
@Tag("security-boundary")
class DeprecatedPermissionExceptionSubclassesTest {

    @Test
    void alreadyExistException_ignoresPassedStatus_usesAlreadyExists() {
        AlreadyExistException ex = new AlreadyExistException("dup", HttpStatus.I_AM_A_TEAPOT);

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.ALREADY_EXISTS);
        assertThat(ex.getMessage()).isEqualTo("dup");
    }

    @Test
    void groupCreationException_ignoresPassedStatus_usesGroupCreationFailed() {
        GroupCreationException ex = new GroupCreationException("could not create group", HttpStatus.I_AM_A_TEAPOT);

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.GROUP_CREATION_FAILED);
    }

    @Test
    void groupNotFoundException_ignoresPassedStatus_usesGroupNotFound() {
        GroupNotFoundException ex = new GroupNotFoundException("no such group", HttpStatus.I_AM_A_TEAPOT);

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.GROUP_NOT_FOUND);
    }

    @Test
    void groupPersistenceException_ignoresPassedStatus_usesGroupPersistenceFailed() {
        GroupPersistenceException ex = new GroupPersistenceException(
                "db write failed", null, HttpStatus.I_AM_A_TEAPOT);

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.GROUP_PERSISTENCE_FAILED);
    }

    @Test
    void groupRoleMappingPersistenceException_ignoresPassedStatus_usesGroupRoleMappingFailed() {
        GroupRoleMappingPersistenceException ex =
                new GroupRoleMappingPersistenceException("mapping failed", HttpStatus.I_AM_A_TEAPOT);

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.GROUP_ROLE_MAPPING_FAILED);
    }

    @Test
    void notFoundException_ignoresPassedStatus_actuallyMapsToGroupNotFound() {
        NotFoundException ex = new NotFoundException("not found", HttpStatus.I_AM_A_TEAPOT);

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.GROUP_NOT_FOUND);
    }

    @Test
    void permissionGroupNotFoundException_ignoresPassedStatus_usesPermissionGroupNotFound() {
        PermissionGroupNotFoundException ex =
                new PermissionGroupNotFoundException("no such permission group", HttpStatus.I_AM_A_TEAPOT);

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.PERMISSION_GROUP_NOT_FOUND);
    }

    @Test
    void roleAssignmentException_ignoresPassedStatus_usesRoleAssignmentFailed() {
        RoleAssignmentException ex = new RoleAssignmentException("assignment failed", HttpStatus.I_AM_A_TEAPOT);

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.ROLE_ASSIGNMENT_FAILED);
    }

    @Test
    void roleNotAssignedException_ignoresPassedStatus_usesRoleNotAssigned() {
        RoleNotAssignedException ex = new RoleNotAssignedException("not assigned", HttpStatus.I_AM_A_TEAPOT);

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.ROLE_NOT_ASSIGNED);
    }

    @Test
    void roleNotFoundException_ignoresPassedStatus_usesRoleNotFound() {
        RoleNotFoundException ex = new RoleNotFoundException("no such role", HttpStatus.I_AM_A_TEAPOT);

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.ROLE_NOT_FOUND);
    }

    @Test
    void rolePersistenceException_ignoresPassedStatus_usesRolePersistenceFailed() {
        RolePersistenceException ex = new RolePersistenceException("db write failed", null, HttpStatus.I_AM_A_TEAPOT);

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.ROLE_PERSISTENCE_FAILED);
    }

    @Test
    void serviceException_ignoresPassedStatus_usesInternalError() {
        ServiceException ex = new ServiceException("service failed", HttpStatus.I_AM_A_TEAPOT);

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.INTERNAL_ERROR);
    }

    @Test
    void subGroupPersistenceException_ignoresPassedStatus_usesSubGroupPersistenceFailed() {
        SubGroupPersistenceException ex =
                new SubGroupPersistenceException("db write failed", null, HttpStatus.I_AM_A_TEAPOT);

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.SUB_GROUP_PERSISTENCE_FAILED);
    }

    @Test
    void userGroupMappingPersistenceException_ignoresPassedStatus_usesUserGroupMappingFailed() {
        UserGroupMappingPersistenceException ex =
                new UserGroupMappingPersistenceException("mapping failed", HttpStatus.I_AM_A_TEAPOT);

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.USER_GROUP_MAPPING_FAILED);
    }

    @Test
    void userNotAddedToGroupException_ignoresPassedStatus_usesUserNotAddedToGroup() {
        UserNotAddedTOGroupException ex =
                new UserNotAddedTOGroupException("could not add user", HttpStatus.I_AM_A_TEAPOT);

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.USER_NOT_ADDED_TO_GROUP);
    }

    @Test
    void userRolePersistenceException_ignoresPassedStatus_usesUserRolePersistenceFailed() {
        UserRolePersistenceException ex =
                new UserRolePersistenceException("persist failed", HttpStatus.I_AM_A_TEAPOT);

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.USER_ROLE_PERSISTENCE_FAILED);
    }
}
