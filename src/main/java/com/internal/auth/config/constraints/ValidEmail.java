package com.internal.auth.config.constraints;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import jakarta.validation.constraints.Pattern;

import java.lang.annotation.Documented;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.*;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

@Documented
@Retention(RUNTIME)
@Constraint(validatedBy = {EmailValidator.class})
@Repeatable(ValidEmail.MultiList.class)
@Target({ METHOD, FIELD, PARAMETER, ANNOTATION_TYPE, TYPE_USE, CONSTRUCTOR })
public @interface ValidEmail {

	String message() default "Valid Email address required. Found ${validatedValue}";
	
	Class<?>[] groups() default { };

	Class<? extends Payload>[] payload() default { };
	
	String regexp() default ".*";

	Pattern.Flag[] flags() default { };
	

	@Target({ METHOD, FIELD, ANNOTATION_TYPE, CONSTRUCTOR, PARAMETER, TYPE_USE })
	@Retention(RUNTIME)
	@Documented
	public @interface MultiList {
		ValidEmail[] value();
	}
}
