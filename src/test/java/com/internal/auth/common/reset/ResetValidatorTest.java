package com.internal.auth.common.reset;

import com.internal.auth.common.exception.BadRequestException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ResetValidatorTest {

    private final ResetValidator resetValidator = new ResetValidator();

    // -- validatePhoneNumberFoResetOperations ---------------------------------
    // Unlike RegistrationValidator's phone check, this one is mandatory - the
    // reset flows always need a phone number to look the account up by.

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "   "})
    void validatePhoneNumberForReset_nullOrBlank_throwsRequired(String phone) {
        assertThatThrownBy(() -> resetValidator.validatePhoneNumberFoResetOperations(phone))
                .isInstanceOf(BadRequestException.class)
                .hasMessage("Phone number is required");
    }

    @ParameterizedTest
    @CsvSource({
            "08012345678, true",
            "+23480123456, true",
            "0801234567, false",
            "080123456789, false",
            "0801234567a, false",
            "'0801 234567', false",
    })
    void validatePhoneNumberForReset_boundaryFormats(String phone, boolean expectedValid) {
        if (expectedValid) {
            assertThatCode(() -> resetValidator.validatePhoneNumberFoResetOperations(phone))
                    .doesNotThrowAnyException();
        } else {
            assertThatThrownBy(() -> resetValidator.validatePhoneNumberFoResetOperations(phone))
                    .isInstanceOf(BadRequestException.class)
                    .hasMessage("Please enter a valid phone number");
        }
    }

    // -- validateOtpFormat -----------------------------------------------------
    // Pattern is built as "\\d{" + expectedLength + "}" and checked with
    // String#matches(), which always requires a full-string match regardless
    // of anchors - so length and character-set boundaries both matter.

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "   "})
    void validateOtpFormat_nullOrBlank_throwsRequired(String otp) {
        assertThatThrownBy(() -> resetValidator.validateOtpFormat(otp, 6))
                .isInstanceOf(BadRequestException.class)
                .hasMessage("Verification code is required");
    }

    @ParameterizedTest
    @CsvSource({
            "123456, 6, true",
            "000000, 6, true",
            "12345, 6, false",
            "1234567, 6, false",
            "12345a, 6, false",
            "1234, 4, true",
            "12345, 4, false",
    })
    void validateOtpFormat_boundaryLengths(String otp, int expectedLength, boolean expectedValid) {
        if (expectedValid) {
            assertThatCode(() -> resetValidator.validateOtpFormat(otp, expectedLength)).doesNotThrowAnyException();
        } else {
            assertThatThrownBy(() -> resetValidator.validateOtpFormat(otp, expectedLength))
                    .isInstanceOf(BadRequestException.class)
                    .hasMessage("The verification code is invalid");
        }
    }

    // -- validateNewPassword ----------------------------------------------------

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "   "})
    void validateNewPassword_nullOrBlankNewPassword_throwsRequired(String newPassword) {
        assertThatThrownBy(() -> resetValidator.validateNewPassword(newPassword, "irrelevant"))
                .isInstanceOf(BadRequestException.class)
                .hasMessage("Password is required");
    }

    @ParameterizedTest
    @CsvSource({
            "1234567, Password must be at least 8 characters",
            "12345678,",
            "123456789,",
    })
    void validateNewPassword_lengthBoundary(String newPassword, String expectedMessage) {
        // confirmPassword deliberately equals newPassword on every row here,
        // so only the length rule is under test - the match rule has its own
        // tests below.
        if (expectedMessage == null) {
            assertThatCode(() -> resetValidator.validateNewPassword(newPassword, newPassword))
                    .doesNotThrowAnyException();
        } else {
            assertThatThrownBy(() -> resetValidator.validateNewPassword(newPassword, newPassword))
                    .isInstanceOf(BadRequestException.class)
                    .hasMessage(expectedMessage);
        }
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "   "})
    void validateNewPassword_nullOrBlankConfirmPassword_throwsPleaseConfirm(String confirmPassword) {
        assertThatThrownBy(() -> resetValidator.validateNewPassword("validpassword1", confirmPassword))
                .isInstanceOf(BadRequestException.class)
                .hasMessage("Please confirm your new password");
    }

    @ParameterizedTest
    @CsvSource({
            "validpassword1, differentpassword1",
            "validpassword1, VALIDPASSWORD1",
            "validpassword1, 'validpassword1 '",
    })
    void validateNewPassword_mismatchedConfirmation_throwsDoNotMatch(String newPassword, String confirmPassword) {
        assertThatThrownBy(() -> resetValidator.validateNewPassword(newPassword, confirmPassword))
                .isInstanceOf(BadRequestException.class)
                .hasMessage("Passwords do not match");
    }

    @ParameterizedTest
    @ValueSource(strings = {"validpassword1", "exactly8"})
    void validateNewPassword_validAndMatching_doesNotThrow(String password) {
        assertThatCode(() -> resetValidator.validateNewPassword(password, password)).doesNotThrowAnyException();
    }
}
