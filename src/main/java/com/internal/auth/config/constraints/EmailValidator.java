package com.internal.auth.config.constraints;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.hazlewood.connor.bottema.emailaddress.EmailAddressValidator;

public class EmailValidator implements ConstraintValidator<ValidEmail, String> {
	

	@Override
	public boolean isValid(String value, ConstraintValidatorContext context) {
		// TODO: Look into javax validation implementation for email validation, as
		// there are a few tricks I'd likely want to replicate
		return EmailAddressValidator.isValid(value);
	}
}