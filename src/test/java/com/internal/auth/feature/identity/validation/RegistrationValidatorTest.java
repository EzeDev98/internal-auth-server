package com.internal.auth.feature.identity.validation;

import com.internal.auth.common.exception.BadRequestException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Unit tests for RegistrationValidator. */
class RegistrationValidatorTest {

    private final RegistrationValidator validator = new RegistrationValidator();

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "   "})
    void validateUsername_nullOrBlank_throwsRequired(String username) {
        assertThatThrownBy(() -> validator.validateUsername(username))
                .isInstanceOf(BadRequestException.class)
                .hasMessage("Username is required");
    }

    @ParameterizedTest
    @CsvSource({
            "a, Username must be at least 3 characters",
            "ab, Username must be at least 3 characters",
            "'  ab  ', Username must be at least 3 characters",
            "abc,",
            "abcd,",
            "'  abc  ',",
            "username123,",
    })
    void validateUsername_boundaryLength(String username, String expectedMessage) {
        if (expectedMessage == null) {
            assertThatCode(() -> validator.validateUsername(username)).doesNotThrowAnyException();
        } else {
            assertThatThrownBy(() -> validator.validateUsername(username))
                    .isInstanceOf(BadRequestException.class)
                    .hasMessage(expectedMessage);
        }
    }

    @Test
    void validateContactInfoPresent_bothActuallyNull_throws() {
        assertThatThrownBy(() -> validator.validateContactInfoPresent(null, null))
                .isInstanceOf(BadRequestException.class)
                .hasMessage("At least one of phone number or email is required");
    }

    @ParameterizedTest
    @CsvSource({
            "'', '', true",
            "'   ', '   ', true",
            "+23480123456, '', false",
            "'', user@example.com, false",
            "+23480123456, user@example.com, false",
    })
    void validateContactInfoPresent_combinations(String phone, String email, boolean expectedThrows) {
        if (expectedThrows) {
            assertThatThrownBy(() -> validator.validateContactInfoPresent(phone, email))
                    .isInstanceOf(BadRequestException.class)
                    .hasMessage("At least one of phone number or email is required");
        } else {
            assertThatCode(() -> validator.validateContactInfoPresent(phone, email)).doesNotThrowAnyException();
        }
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "   "})
    void validatePhoneNumberIfPresent_nullOrBlank_isSkipped(String phone) {
        assertThatCode(() -> validator.validatePhoneNumberIfPresent(phone)).doesNotThrowAnyException();
    }

    @ParameterizedTest
    @CsvSource({
            "08012345678, true",
            "+23480123456, true",
            "0801234567, false",
            "080123456789, false",
            "+234801234567, false",
            "0801234567a, false",
            "'0801 234567', false",
            "++2348012345, false",
            "-08012345678, false",
    })
    void validatePhoneNumberIfPresent_boundaryFormats(String phone, boolean expectedValid) {
        if (expectedValid) {
            assertThatCode(() -> validator.validatePhoneNumberIfPresent(phone)).doesNotThrowAnyException();
        } else {
            assertThatThrownBy(() -> validator.validatePhoneNumberIfPresent(phone))
                    .isInstanceOf(BadRequestException.class)
                    .hasMessage("Please enter a valid phone number");
        }
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "   "})
    void validateEmailIfPresent_nullOrBlank_isSkipped(String email) {
        assertThatCode(() -> validator.validateEmailIfPresent(email)).doesNotThrowAnyException();
    }

    @ParameterizedTest
    @CsvSource({
            "user@example.com, true",
            "'first.last+tag@sub.example.co', true",
            "user@domain.corporate, true",
            "not-an-email, false",
            "missing-at-sign.com, false",
            "'user@.com', false",
            "user@domain, false",
            "user@domain.c, false",
            "'@example.com', false",
            "'us er@example.com', false",
    })
    void validateEmailIfPresent_boundaryFormats(String email, boolean expectedValid) {
        if (expectedValid) {
            assertThatCode(() -> validator.validateEmailIfPresent(email)).doesNotThrowAnyException();
        } else {
            assertThatThrownBy(() -> validator.validateEmailIfPresent(email))
                    .isInstanceOf(BadRequestException.class)
                    .hasMessage("Please enter a valid email address");
        }
    }
}
