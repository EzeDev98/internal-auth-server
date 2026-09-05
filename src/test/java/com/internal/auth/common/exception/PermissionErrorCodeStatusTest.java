package com.internal.auth.common.exception;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.http.HttpStatus;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Tag;

/**
 * Step 5C - locks in the numeric code and HTTP status for every
 * PermissionErrorCode value, so a future edit that reorders, renumbers, or
 * changes the status of one of these fails loudly here instead of silently
 * changing a documented API contract.
 */
@Tag("security-boundary")
class PermissionErrorCodeStatusTest {

    @ParameterizedTest
    @CsvSource({
            "ROLE_NOT_FOUND, 12001, NOT_FOUND",
            "GROUP_NOT_FOUND, 12002, NOT_FOUND",
            "SUB_GROUP_NOT_FOUND, 12003, NOT_FOUND",
            "SUPER_GROUP_NOT_FOUND, 12004, NOT_FOUND",
            "PERMISSION_GROUP_NOT_FOUND, 12005, NOT_FOUND",
            "USER_NOT_FOUND, 12006, NOT_FOUND",
            "AMBIGUOUS_USERNAME, 12007, CONFLICT",
            "ALREADY_EXISTS, 12101, CONFLICT",
            "DUPLICATE_ROLE_ASSIGNMENT, 12103, CONFLICT",
            "EMPTY_FIELD, 12201, BAD_REQUEST",
            "EMPTY_REQUEST, 12202, BAD_REQUEST",
            "ROLE_NOT_ASSIGNED, 12203, BAD_REQUEST",
            "USER_NOT_ADDED_TO_GROUP, 12204, BAD_REQUEST",
            "PERMISSION_OPERATION_FAILED, 12303, INTERNAL_SERVER_ERROR",
            "ROLE_ASSIGNMENT_FAILED, 12304, INTERNAL_SERVER_ERROR",
            "ROLE_ASSIGNMENT_VERIFICATION_FAILED, 12305, INTERNAL_SERVER_ERROR",
            "ROLE_PERSISTENCE_FAILED, 12401, INTERNAL_SERVER_ERROR",
            "GROUP_PERSISTENCE_FAILED, 12402, INTERNAL_SERVER_ERROR",
            "SUB_GROUP_PERSISTENCE_FAILED, 12403, INTERNAL_SERVER_ERROR",
            "GROUP_ROLE_MAPPING_FAILED, 12404, INTERNAL_SERVER_ERROR",
            "USER_GROUP_MAPPING_FAILED, 12405, INTERNAL_SERVER_ERROR",
            "USER_ROLE_PERSISTENCE_FAILED, 12406, INTERNAL_SERVER_ERROR",
            "ROLE_RETRIEVAL_FAILED, 12407, INTERNAL_SERVER_ERROR",
            "ROLLBACK_FAILED, 12408, INTERNAL_SERVER_ERROR",
            "INTERNAL_ERROR, 12901, INTERNAL_SERVER_ERROR",
            "ROLE_CREATION_FAILED, 12902, INTERNAL_SERVER_ERROR",
            "GROUP_CREATION_FAILED, 12903, INTERNAL_SERVER_ERROR",
    })
    void locksInCodeAndHttpStatusForEveryPermissionErrorCode(String enumName, int expectedCode, String expectedStatus) {
        PermissionErrorCode errorCode = PermissionErrorCode.valueOf(enumName);

        assertThat(errorCode.getCode()).isEqualTo(expectedCode);
        assertThat(errorCode.getHttpStatus()).isEqualTo(HttpStatus.valueOf(expectedStatus));
    }

    @Test
    void everyEnumConstantIsCoveredByTheTableAbove() {
        // If this fails, a new PermissionErrorCode was added without adding
        // a row to the @CsvSource table above locking in its code and
        // status - or one was removed without removing its row.
        assertThat(PermissionErrorCode.values()).hasSize(27);
    }

    @Test
    void noTwoErrorCodesShareTheSameNumericCode() {
        long distinctCodes = Arrays.stream(PermissionErrorCode.values())
                .map(PermissionErrorCode::getCode)
                .distinct()
                .count();

        assertThat(distinctCodes).isEqualTo(PermissionErrorCode.values().length);
    }
}
