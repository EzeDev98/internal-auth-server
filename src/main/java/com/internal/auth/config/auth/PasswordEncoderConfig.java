package com.internal.auth.config.auth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Split out of {@link WebSecurityConfig} to break a circular bean
 * dependency. {@code PasswordEncoder} used to be a {@code @Bean} method on
 * {@code WebSecurityConfig} itself, but {@code WebSecurityConfig}'s own
 * constructor (via {@code @RequiredArgsConstructor}) depends on
 * {@code JwtSessionTrackingFilter}, which depends on
 * {@code SessionManagementServiceImpl}, which depends on
 * {@code ClientApplicationServiceImpl}, which depends on
 * {@code PasswordEncoder}. Producing that bean therefore required
 * {@code WebSecurityConfig} to already be constructed, which required
 * {@code JwtSessionTrackingFilter} to already exist, which required
 * {@code PasswordEncoder} to already exist - a genuine cycle, not a false
 * positive. Spring Boot 4.1.1 / Spring 7.x refuses circular references by
 * default, and setting {@code spring.main.allow-circular-references=true}
 * would only paper over it. There is no real reason {@code PasswordEncoder}
 * needs to live on {@code WebSecurityConfig} specifically - moving it into
 * this standalone, dependency-free {@code @Configuration} class breaks the
 * cycle. Nothing about the bean itself changes: it's still a single
 * {@code BCryptPasswordEncoder}, just no longer entangled with
 * {@code WebSecurityConfig}'s own construction.
 */
@Configuration
public class PasswordEncoderConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
