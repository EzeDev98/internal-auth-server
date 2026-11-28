package com.internal.auth.common.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

/** Error codes and HTTP statuses for the permission module. */
@Getter
public enum PermissionErrorCode {
    ROLE_NOT_FOUND(12001, "Role not found", HttpStatus.NOT_FOUND),
    GROUP_NOT_FOUND(12002, "Group not found", HttpStatus.NOT_FOUND),
    SUB_GROUP_NOT_FOUND(12003, "Sub-group not found", HttpStatus.NOT_FOUND),
    SUPER_GROUP_NOT_FOUND(12004, "Super-group not found", HttpStatus.NOT_FOUND),
    PERMISSION_GROUP_NOT_FOUND(12005, "Permission group not found", HttpStatus.NOT_FOUND),
    USER_NOT_FOUND(12006, "User not found", HttpStatus.NOT_FOUND),
    AMBIGUOUS_USERNAME(12007, "Username exists in more than one client application; cannot resolve uniquely", HttpStatus.CONFLICT),

    ALREADY_EXISTS(12101, "Resource already exists", HttpStatus.CONFLICT),
    DUPLICATE_ROLE_ASSIGNMENT(12103, "Role is already assigned to this user", HttpStatus.CONFLICT),

    EMPTY_FIELD(12201, "Required field is missing or empty", HttpStatus.BAD_REQUEST),
    EMPTY_REQUEST(12202, "Request body is empty", HttpStatus.BAD_REQUEST),
    ROLE_NOT_ASSIGNED(12203, "Role has not been assigned", HttpStatus.BAD_REQUEST),
    USER_NOT_ADDED_TO_GROUP(12204, "User could not be added to the group", HttpStatus.BAD_REQUEST),

    PERMISSION_OPERATION_FAILED(12303, "Permission operation failed", HttpStatus.INTERNAL_SERVER_ERROR),
    ROLE_ASSIGNMENT_FAILED(12304, "Role assignment operation failed", HttpStatus.INTERNAL_SERVER_ERROR),
    ROLE_ASSIGNMENT_VERIFICATION_FAILED(12305, "Could not verify role assignment", HttpStatus.INTERNAL_SERVER_ERROR),

    ROLE_PERSISTENCE_FAILED(12401, "Failed to save role to database", HttpStatus.INTERNAL_SERVER_ERROR),
    GROUP_PERSISTENCE_FAILED(12402, "Failed to save group to database", HttpStatus.INTERNAL_SERVER_ERROR),
    SUB_GROUP_PERSISTENCE_FAILED(12403, "Failed to save sub-group to database", HttpStatus.INTERNAL_SERVER_ERROR),
    GROUP_ROLE_MAPPING_FAILED(12404, "Failed to map role to group", HttpStatus.INTERNAL_SERVER_ERROR),
    USER_GROUP_MAPPING_FAILED(12405, "Failed to map user to group", HttpStatus.INTERNAL_SERVER_ERROR),
    USER_ROLE_PERSISTENCE_FAILED(12406, "Failed to persist user role", HttpStatus.INTERNAL_SERVER_ERROR),
    ROLE_RETRIEVAL_FAILED(12407, "Failed to retrieve roles", HttpStatus.INTERNAL_SERVER_ERROR),
    ROLLBACK_FAILED(12408, "Operation failed and rollback also failed — manual intervention required", HttpStatus.INTERNAL_SERVER_ERROR),

    INTERNAL_ERROR(12901, "An unexpected internal error occurred", HttpStatus.INTERNAL_SERVER_ERROR),
    ROLE_CREATION_FAILED(12902, "Role creation operation failed", HttpStatus.INTERNAL_SERVER_ERROR),
    GROUP_CREATION_FAILED(12903, "Group creation operation failed", HttpStatus.INTERNAL_SERVER_ERROR);

    private final int code;
    private final String message;
    private final HttpStatus httpStatus;

    PermissionErrorCode(int code, String message, HttpStatus httpStatus) {
        this.code = code;
        this.message = message;
        this.httpStatus = httpStatus;
    }
}
