package com.internal.auth.feature.identity.validation;

import com.internal.auth.common.exception.BadRequestException;
import org.springframework.stereotype.Component;

/** Validates registration input. */
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

    public void validateContactInfoPresent(String phoneNumber, String email) {
        boolean hasPhone = phoneNumber != null && !phoneNumber.isBlank();
        boolean hasEmail = email != null && !email.isBlank();
        if (!hasPhone && !hasEmail) {
            throw new BadRequestException("At least one of phone number or email is required");
        }
    }

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
