package com.internal.auth.feature.identity.service.impl;

import com.internal.auth.common.exception.UserAlreadyExistsException;
import com.internal.auth.common.reset.ResetValidator;
import com.internal.auth.feature.identity.dto.RegisterRequest;
import com.internal.auth.feature.identity.dto.RegisterResponse;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.identity.service.EmailVerificationService;
import com.internal.auth.feature.identity.service.RegistrationService;
import com.internal.auth.feature.identity.validation.RegistrationValidator;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Step 10A/10B/10C - the first Stage 3/4 (Authentication) work, and the
 * first code path in this app that creates a User row itself. Everything
 * before this (Stage 2) only ever read or updated an already-existing row.
 *
 * Per the Step 10A scoping decisions: newly registered users are enabled
 * immediately (emailVerified/phoneVerified stay false and independent -
 * Step 10C's verification flow sets emailVerified later, not as a gate on
 * registration itself), and this returns a plain confirmation rather than
 * a session/token (token issuance is Step 12).
 *
 * Conflict messages ("username/phone/email or password is incorrect")
 * deliberately never say "already exists". Step 10B: save() is wrapped to
 * catch DataIntegrityViolationException as a defensive backstop against
 * the uniqueness pre-checks below being check-then-act, not atomic.
 * Step 10C: on successful save, if an email was supplied, a verification
 * link is sent - failure to send never fails registration itself.
 */
@Service
@RequiredArgsConstructor
public class RegistrationServiceImpl implements RegistrationService {

    private static final Logger log = LoggerFactory.getLogger(RegistrationServiceImpl.class);

    private final UserRepository userRepository;
    private final RegistrationValidator registrationValidator;
    private final ResetValidator resetValidator;
    private final PasswordEncoder passwordEncoder;
    private final EmailVerificationService emailVerificationService;

    @Override
    @Transactional
    public RegisterResponse register(RegisterRequest request) {
        registrationValidator.validateUsername(request.getUsername());
        registrationValidator.validateContactInfoPresent(request.getPhoneNumber(), request.getEmail());
        registrationValidator.validatePhoneNumberIfPresent(request.getPhoneNumber());
        registrationValidator.validateEmailIfPresent(request.getEmail());

        // Reuses ResetValidator's password rules directly, per the Step 10A
        // decision to keep one password policy definition rather than two.
        resetValidator.validateNewPassword(request.getPassword(), request.getConfirmPassword());

        String username = request.getUsername().trim();
        if (userRepository.findByUsername(username).isPresent()) {
            throw new UserAlreadyExistsException("Username or password is incorrect");
        }

        String phoneNumber = normalize(request.getPhoneNumber());
        if (phoneNumber != null && userRepository.findByPhoneNumber(phoneNumber).isPresent()) {
            throw new UserAlreadyExistsException("Phone number or password is incorrect");
        }

        String email = normalize(request.getEmail());
        if (email != null && userRepository.findByEmail(email).isPresent()) {
            throw new UserAlreadyExistsException("Email or password is incorrect");
        }

        User user = new User();
        user.setUsername(username);
        user.setPhoneNumber(phoneNumber);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        // enabled defaults to true, emailVerified/phoneVerified default to
        // false on the entity itself - left untouched here deliberately.

        User saved;
        try {
            // IDENTITY generation (see User's @GeneratedValue) means save()
            // issues the INSERT immediately rather than deferring it to a
            // later flush, so a unique-constraint race is caught right here.
            saved = userRepository.save(user);
        } catch (DataIntegrityViolationException e) {
            log.warn("Registration lost a uniqueness race at save-time (username={})", username);
            throw new UserAlreadyExistsException("Unable to create account with the provided details");
        }

        // Step 10C: soft-fail by design - sendVerificationEmail already
        // swallows its own delivery/provider exceptions internally, so a
        // failure here never rolls back the account that was just created.
        emailVerificationService.sendVerificationEmail(saved);

        log.info("New user registered, id={}", saved.getId());

        return new RegisterResponse(saved.getId(), saved.getUsername(),
                "Account created successfully.");
    }

    private String normalize(String value) {
        return (value == null || value.isBlank()) ? null : value.trim();
    }
}
