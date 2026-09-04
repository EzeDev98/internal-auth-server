package com.internal.auth.common.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

import java.util.Map;

/**
 * Single unified exception for the Permission module.
 *
 * <pre>{@code
 * throw PermissionException.roleNotFound("BUYER");
 * throw PermissionException.groupNotFound("WealthMarket-Buyers");
 * throw PermissionException.emptyField("Username and role name are mandatory");
 * throw PermissionException.operationFailed("Unexpected error during role creation", cause);
 * throw PermissionException.rollbackFailed("Manual intervention required", cause);
 * throw PermissionException.of(PermissionErrorCode.USER_ROLE_PERSISTENCE_FAILED, "detail");
 * }</pre>
 */
@Getter
public class PermissionException extends RuntimeException {

    private final PermissionErrorCode errorCode;
    private final HttpStatus status;
    private final Map<String, Object> metadata;

    public PermissionException(PermissionErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
        this.status = errorCode.getHttpStatus();
        this.metadata = null;
    }

    public PermissionException(PermissionErrorCode errorCode, String customMessage) {
        super(customMessage);
        this.errorCode = errorCode;
        this.status = errorCode.getHttpStatus();
        this.metadata = null;
    }

    public PermissionException(PermissionErrorCode errorCode, String customMessage,
                               Throwable cause) {
        super(customMessage, cause);
        this.errorCode = errorCode;
        this.status = errorCode.getHttpStatus();
        this.metadata = null;
    }

    public PermissionException(PermissionErrorCode errorCode, Throwable cause) {
        super(errorCode.getMessage(), cause);
        this.errorCode = errorCode;
        this.status = errorCode.getHttpStatus();
        this.metadata = null;
    }

    public PermissionException(PermissionErrorCode errorCode, String customMessage,
                               Map<String, Object> metadata) {
        super(customMessage);
        this.errorCode = errorCode;
        this.status = errorCode.getHttpStatus();
        this.metadata = metadata;
    }

    // ── Generic factories ─────────────────────────────────────────────────────

    public static PermissionException of(PermissionErrorCode code) {
        return new PermissionException(code);
    }

    public static PermissionException of(PermissionErrorCode code, String message) {
        return new PermissionException(code, message);
    }

    public static PermissionException of(PermissionErrorCode code, String message,
                                         Throwable cause) {
        return new PermissionException(code, message, cause);
    }

    public static PermissionException of(PermissionErrorCode code, Throwable cause) {
        return new PermissionException(code, cause);
    }

    // ── Resource not found ────────────────────────────────────────────────────

    public static PermissionException roleNotFound(String detail) {
        return new PermissionException(PermissionErrorCode.ROLE_NOT_FOUND, detail);
    }

    public static PermissionException groupNotFound(String detail) {
        return new PermissionException(PermissionErrorCode.GROUP_NOT_FOUND, detail);
    }

    public static PermissionException subGroupNotFound(String detail) {
        return new PermissionException(PermissionErrorCode.SUB_GROUP_NOT_FOUND, detail);
    }

    public static PermissionException superGroupNotFound(String detail) {
        return new PermissionException(PermissionErrorCode.SUPER_GROUP_NOT_FOUND, detail);
    }

    public static PermissionException permissionGroupNotFound(String detail) {
        return new PermissionException(PermissionErrorCode.PERMISSION_GROUP_NOT_FOUND, detail);
    }

    public static PermissionException userNotFound(String detail) {
        return new PermissionException(PermissionErrorCode.USER_NOT_FOUND, detail);
    }

    public static PermissionException notFound(String detail) {
        return new PermissionException(PermissionErrorCode.GROUP_NOT_FOUND, detail);
    }

    // ── Conflict / duplicate ──────────────────────────────────────────────────

    public static PermissionException alreadyExists(String detail) {
        return new PermissionException(PermissionErrorCode.ALREADY_EXISTS, detail);
    }


    public static PermissionException duplicateRoleAssignment(String detail) {
        return new PermissionException(PermissionErrorCode.DUPLICATE_ROLE_ASSIGNMENT, detail);
    }

    // ── Business rule violations / invalid input ──────────────────────────────

    public static PermissionException emptyField(String detail) {
        return new PermissionException(PermissionErrorCode.EMPTY_FIELD, detail);
    }

    public static PermissionException emptyRequest(String detail) {
        return new PermissionException(PermissionErrorCode.EMPTY_REQUEST, detail);
    }

    public static PermissionException roleNotAssigned(String detail) {
        return new PermissionException(PermissionErrorCode.ROLE_NOT_ASSIGNED, detail);
    }

    public static PermissionException userNotAddedToGroup(String detail) {
        return new PermissionException(PermissionErrorCode.USER_NOT_ADDED_TO_GROUP, detail);
    }

    // ── External integration ──────────────────────────────────────



    public static PermissionException operationFailed(String detail) {
        return new PermissionException(PermissionErrorCode.PERMISSION_OPERATION_FAILED, detail);
    }

    public static PermissionException operationFailed(String detail, Throwable cause) {
        return new PermissionException(PermissionErrorCode.PERMISSION_OPERATION_FAILED, detail, cause);
    }

    public static PermissionException roleAssignmentFailed(String detail) {
        return new PermissionException(PermissionErrorCode.ROLE_ASSIGNMENT_FAILED, detail);
    }

    public static PermissionException roleAssignmentVerificationFailed(String detail) {
        return new PermissionException(PermissionErrorCode.ROLE_ASSIGNMENT_VERIFICATION_FAILED, detail);
    }

    // ── Persistence / database ────────────────────────────────────────────────

    public static PermissionException rolePersistenceFailed(String detail) {
        return new PermissionException(PermissionErrorCode.ROLE_PERSISTENCE_FAILED, detail);
    }

    public static PermissionException groupPersistenceFailed(String detail) {
        return new PermissionException(PermissionErrorCode.GROUP_PERSISTENCE_FAILED, detail);
    }

    public static PermissionException subGroupPersistenceFailed(String detail) {
        return new PermissionException(PermissionErrorCode.SUB_GROUP_PERSISTENCE_FAILED, detail);
    }

    public static PermissionException groupRoleMappingFailed(String detail) {
        return new PermissionException(PermissionErrorCode.GROUP_ROLE_MAPPING_FAILED, detail);
    }

    public static PermissionException userGroupMappingFailed(String detail) {
        return new PermissionException(PermissionErrorCode.USER_GROUP_MAPPING_FAILED, detail);
    }

    public static PermissionException userRolePersistenceFailed(String detail) {
        return new PermissionException(PermissionErrorCode.USER_ROLE_PERSISTENCE_FAILED, detail);
    }

    public static PermissionException roleRetrievalFailed(String detail) {
        return new PermissionException(PermissionErrorCode.ROLE_RETRIEVAL_FAILED, detail);
    }

    public static PermissionException rollbackFailed(String detail) {
        return new PermissionException(PermissionErrorCode.ROLLBACK_FAILED, detail);
    }

    public static PermissionException rollbackFailed(String detail, Throwable cause) {
        return new PermissionException(PermissionErrorCode.ROLLBACK_FAILED, detail, cause);
    }

    // ── System / infrastructure ───────────────────────────────────────────────

    public static PermissionException internalError(String detail) {
        return new PermissionException(PermissionErrorCode.INTERNAL_ERROR, detail);
    }

    public static PermissionException internalError(String detail, Throwable cause) {
        return new PermissionException(PermissionErrorCode.INTERNAL_ERROR, detail, cause);
    }

    public static PermissionException roleCreationFailed(String detail) {
        return new PermissionException(PermissionErrorCode.ROLE_CREATION_FAILED, detail);
    }

    public static PermissionException groupCreationFailed(String detail) {
        return new PermissionException(PermissionErrorCode.GROUP_CREATION_FAILED, detail);
    }
}