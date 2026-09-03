package com.internal.auth.feature.identity.validation;

import com.internal.auth.common.exception.BadRequestException;
import org.springframework.stereotype.Component;

/**
 * Input validation for registration (Step 10A). Sibling to ResetValidator
 * (common.reset) - that class validates the OTP-reset flows; this one
 * validates account creation. Kept separate rather than merged into one
 * grab-bag validator, even though a couple of rules (phone-number format)
 * happen to coincide, since the two validate different request shapes for
 * different features.
 *
 * Note on naming: ResetValidator#validateNewPassword's Javadoc has referred
 * to "RegistrationValidator" by name since before this class existed - it
 * didn't exist anywhere in the repo until this file. That comment also had
 * the relationship backwards: this class does not own the password rule.
 * Per the Step 10A decision, registration reuses
 * ResetValidator#validateNewPassword directly for password rules, so
 * ResetValidator remains the one place that rule is defined - this class
 * only owns username/phone/email format and presence checks.
 */
@Component
public class RegistrationValidator {

    private static final String PHONE_PATTERN = "^\\+?[0-9]{11}$";
    private static final String EMAIL_PATTERN = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$";
    private static final int MIN_USERNAME_LENGTH = 3;

    public void validateUsername(String username) {
        if (username == null || username.isBlank()) {
            throw new BadRequestException("Username is required");
        }
        if (username.trim().length() < MIN_USERNAME_LENGTH) {
            throw new BadRequestException("Username must be at least " + MIN_USERNAME_LENGTH + " characters");
        }
    }

    /**
     * Enforces the same "at least one of phone or email" rule the V1
     * migration's ck_users_phone_or_email CHECK constraint enforces at the
     * database level (see User's class Javadoc) - this is the
     * application-level counterpart, so a caller gets a friendly 400
     * instead of a raw constraint-violation error.
     */
    public void validateContactInfoPresent(String phoneNumber, String email) {
        boolean hasPhone = phoneNumber != null && !phoneNumber.isBlank();
        boolean hasEmail = email != null && !email.isBlank();
        if (!hasPhone && !hasEmail) {
            throw new BadRequestException("At least one of phone number or email is required");
        }
    }

    /**
     * Phone number is optional at registration (see validateContactInfoPresent
     * for the "at least one" rule), so this only checks format when a value
     * was actually supplied - unlike
     * ResetValidator#validatePhoneNumberFoResetOperations, which treats the
     * phone number as mandatory. Same format rule as that method
     * intentionally, since it's the same kind of value; duplicated rather
     * than called because the two methods disagree on whether a blank value
     * is even an error.
     */
    public void validatePhoneNumberIfPresent(String phoneNumber) {
        if (phoneNumber == null || phoneNumber.isBlank()) {
            return;
        }
        if (!phoneNumber.matches(PHONE_PATTERN)) {
            throw new BadRequestException("Please enter a valid phone number");
        }
    }

    public void validateEmailIfPresent(String email) {
        if (email == null || email.isBlank()) {
            return;
        }
        if (!email.matches(EMAIL_PATTERN)) {
            throw new BadRequestException("Please enter a valid email address");
        }
    }
}
