package com.internal.auth.testsupport;

import org.springframework.test.web.servlet.ResultMatcher;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

/** JSON path assertions for the standard API response envelope. */
public final class ApiResponseAssertions {

    private ApiResponseAssertions() {
    }

    public static ResultMatcher success() {
        return jsonPath("$.success").value(true);
    }

    public static ResultMatcher failure() {
        return jsonPath("$.success").value(false);
    }

    public static ResultMatcher message(String expected) {
        return jsonPath("$.message").value(expected);
    }

    public static ResultMatcher errorCode(String expected) {
        return jsonPath("$.errorCode").value(expected);
    }

    public static ResultMatcher dataFieldPresent() {
        return jsonPath("$.data").exists();
    }

    public static ResultMatcher dataFieldAbsentOrNull() {
        return jsonPath("$.data").doesNotExist();
    }
}
