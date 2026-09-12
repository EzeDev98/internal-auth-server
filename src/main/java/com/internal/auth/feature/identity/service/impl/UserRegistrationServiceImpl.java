package com.internal.auth.feature.identity.service.impl;

import com.internal.auth.common.exception.UserAlreadyExistsException;
import com.internal.auth.common.reset.ResetValidator;
import com.internal.auth.common.response.BaseResponse;
import com.internal.auth.feature.identity.dto.request.RegisterRequest;
import com.internal.auth.feature.identity.dto.response.RegisterResponse;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.identity.service.EmailVerificationService;
import com.internal.auth.feature.identity.service.PhoneVerificationService;
import com.internal.auth.feature.identity.service.UserRegistrationService;
import com.internal.auth.feature.identity.validation.RegistrationValidator;
import com.internal.auth.feature.rbac.service.UserService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.UUID;

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
 * link is sent - failure to send never fails registration itself. If a
 * phone number was supplied, a verification OTP is sent the same way.
 *
 * Default-role gap fix: every fresh user is enrolled into the default
 * permission group/role via the existing (previously never-invoked)
 * UserService.addUserToDefaultPermissionGroup orchestration, so a brand
 * new account isn't locked out of every role-gated endpoint until an
 * admin manually assigns one. That orchestration is itself designed to
 * never throw - it always returns a BaseResponse - so this is soft-fail
 * and log-only here too, same as the email/phone verification sends
 * above it. Note this reuses the RBAC subsystem as-is, which (like the
 * rest of roles/permission groups) is not yet scoped by
 * clientApplicationId - that's a separate, already-deferred gap, not
 * something this fix changes.
 *
 * Multi-tenant redesign, registration step: clientApplicationId is
 * resolved by RegistrationController from the caller's HTTP Basic client
 * credentials before this method ever runs - every uniqueness check below
 * and the created User row are scoped to it, since username/phone/email
 * are now only unique within one client_application_id (see User's class
 * Javadoc and the V8 migration).
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class UserRegistrationServiceImpl implements UserRegistrationService {

    private final UserRepository userRepository;
    private final RegistrationValidator registrationValidator;
    private final ResetValidator resetValidator;
    private final PasswordEncoder passwordEncoder;
    private final EmailVerificationService emailVerificationService;
    private final PhoneVerificationService phoneVerificationService;
    private final UserService userService;

    @Override
    @Transactional
    public RegisterResponse register(RegisterRequest request, Long clientApplicationId) {
        registrationValidator.validateUsername(request.getUsername());
        registrationValidator.validateContactInfoPresent(request.getPhoneNumber(), request.getEmail());
        registrationValidator.validatePhoneNumberIfPresent(request.getPhoneNumber());
        registrationValidator.validateEmailIfPresent(request.getEmail());

        // Reuses ResetValidator's password rules directly, per the Step 10A
        // decision to keep one password policy definition rather than two.
        resetValidator.validateNewPassword(request.getPassword(), request.getConfirmPassword());

        String username = request.getUsername().trim();
        if (userRepository.findByUsernameAndClientApplicationId(username, clientApplicationId).isPresent()) {
            throw new UserAlreadyExistsException("Username or password is incorrect");
        }

        String phoneNumber = normalize(request.getPhoneNumber());
        if (phoneNumber != null && userRepository.findByPhoneNumberAndClientApplicationId(phoneNumber, clientApplicationId).isPresent()) {
            throw new UserAlreadyExistsException("Phone number or password is incorrect");
        }

        String email = normalize(request.getEmail());
        if (email != null && userRepository.findByEmailAndClientApplicationId(email, clientApplicationId).isPresent()) {
            throw new UserAlreadyExistsException("Email or password is incorrect");
        }

        User user = new User();
        user.setClientApplicationId(clientApplicationId);
        user.setUsername(username);
        user.setPhoneNumber(phoneNumber);
        user.setEmail(email);
        user.setInternalAuthUserId("IA_" + UUID.randomUUID());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        // enabled defaults to true, emailVerified/phoneVerified default to
        // false on the entity itself - left untouched here deliberately.

        User savedUser;
        try {
            // IDENTITY generation (see User's @GeneratedValue) means save()
            // issues the INSERT immediately rather than deferring it to a
            // later flush, so a unique-constraint race is caught right here.
            savedUser = userRepository.save(user);
        } catch (DataIntegrityViolationException e) {
            log.warn("Registration lost a uniqueness race at save-time (username={})", username);
            throw new UserAlreadyExistsException("Unable to create account with the provided details");
        }

        // Step 10C: soft-fail by design - sendVerificationEmail already
        // swallows its own delivery/provider exceptions internally, so a
        // failure here never rolls back the account that was just created.
        emailVerificationService.sendVerificationEmail(savedUser);

        // Self-service phone verification fix: same soft-fail contract as
        // email above - sendVerificationOtp swallows its own delivery
        // failures internally.
        phoneVerificationService.sendVerificationOtp(savedUser);

        // Default-role gap fix: enroll the new user into the default
        // permission group/role. Must run strictly AFTER this transaction
        // commits - addUserToDefaultPermissionGroup runs in its own
        // REQUIRES_NEW transaction/connection, which correctly cannot see
        // this transaction's INSERT until it is committed. Calling it
        // synchronously from inside this still-open transaction made
        // EntityUtilityService#getUser fail with USER_NOT_FOUND on every
        // registration, and because that failure gets swallowed internally
        // instead of rethrown, addUserToDefaultPermissionGroup's own
        // REQUIRES_NEW transaction ended up rollback-only on a normal
        // method return - which Spring turns into an UnexpectedRollbackException
        // at commit time. That exception was never caught here, so it
        // propagated out of register() and rolled back THIS transaction too
        // (the user row included), surfacing as a 500 - even though the
        // email/OTP sends above had already fired, since those aren't part
        // of the DB transaction. Deferring to afterCommit fixes the root
        // cause: by the time this runs, the user row is guaranteed visible.
        Runnable assignDefaultRole = () -> {
            BaseResponse roleAssignment = userService.addUserToDefaultPermissionGroup(savedUser.getUsername());
            if (roleAssignment.getStatusCode() != HttpServletResponse.SC_CREATED) {
                log.warn("Default role assignment did not complete cleanly for user id {} (status={}, message={})", savedUser.getId(), roleAssignment.getStatusCode(), roleAssignment.getDescription());
            }
        };

        // Only defer via afterCommit when a transaction is actually active
        // to attach to (the normal HTTP-request path, where register()
        // itself is @Transactional). Callers with no active transaction
        // synchronization - e.g. a unit test invoking register() directly
        // against mocks, or any future caller outside a transactional
        // context - have no commit event to defer to, so run it inline
        // immediately instead, matching the pre-fix behavior for them.
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    assignDefaultRole.run();
                }
            });
        } else {
            assignDefaultRole.run();
        }

        log.info("New user registered, id={}", savedUser.getId());

        return new RegisterResponse(savedUser.getInternalAuthUserId(), savedUser.getUsername(), "Account created successfully.");
    }

    private String normalize(String value) {
        return (value == null || value.isBlank()) ? null : value.trim();
    }
}
