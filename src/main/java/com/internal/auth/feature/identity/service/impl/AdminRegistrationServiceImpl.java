package com.internal.auth.feature.identity.service.impl;

import com.internal.auth.common.exception.PermissionException;
import com.internal.auth.common.exception.UserAlreadyExistsException;
import com.internal.auth.common.reset.ResetValidator;
import com.internal.auth.common.response.BaseResponse;
import com.internal.auth.common.security.AuthenticationHelper;
import com.internal.auth.feature.identity.dto.request.AdminRegisterRequest;
import com.internal.auth.feature.identity.dto.response.AdminRegisterResponse;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.identity.service.AdminRegistrationService;
import com.internal.auth.feature.identity.validation.RegistrationValidator;
import com.internal.auth.feature.rbac.model.Role;
import com.internal.auth.feature.rbac.repository.RolesRepository;
import com.internal.auth.feature.rbac.repository.UserRolesRepository;
import com.internal.auth.feature.rbac.service.UserService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

import static com.internal.auth.common.constant.AppConstant.ADMIN_ROLE;
import static com.internal.auth.common.constant.AppConstant.ADMIN_ROLE_DESCRIPTION;

/**
 * Admin bootstrap registration - the equivalent of standing up Keycloak's
 * master realm admin, minus the seeding stress. Reuses RegistrationServiceImpl's
 * exact validation/uniqueness/save pattern (see that class for the shared
 * rationale on conflict-message wording and the DataIntegrityViolationException
 * backstop), with three deliberate differences:
 *
 * <p><b>Self-limiting bootstrap gate:</b> POST /api/v1/admin/register is
 * permitAll in WebSecurityConfig (there is, by definition, no bearer token
 * to present for the very first admin) - so the gate is enforced here in
 * code instead of @PreAuthorize. Open with no auth at all only until the
 * first create-admin user exists; once one does, the caller must already be
 * an authenticated admin (AuthenticationHelper#isAdmin) to create another.
 *
 * <p><b>Pre-verified contact info:</b> whichever of phoneNumber/email is
 * supplied is marked verified immediately rather than routed through
 * EmailVerificationService/PhoneVerificationService - an admin account is
 * created by (or, for the first one, in place of) someone with server
 * access, not through public self-service, and this avoids
 * LoginServiceImpl's describeUnverifiedContactMethods gate blocking the
 * admin's very first login.
 *
 * <p><b>Non-soft-fail role assignment:</b> RegistrationServiceImpl's default-
 * role wiring logs and moves on if UserService#addUserToDefaultPermissionGroup
 * doesn't return 201, because a regular user missing their default role is
 * recoverable later by an admin. That's not true here - an "admin" account
 * that silently ends up without the create-admin role would be a broken
 * account nobody could fix (no admin would exist yet to grant it) - so a
 * failure here throws and, being @Transactional, rolls back the whole
 * registration instead.
 */
@Service
@RequiredArgsConstructor
public class AdminRegistrationServiceImpl implements AdminRegistrationService {

    private static final Logger log = LoggerFactory.getLogger(AdminRegistrationServiceImpl.class);

    private final UserRepository userRepository;
    private final RegistrationValidator registrationValidator;
    private final ResetValidator resetValidator;
    private final PasswordEncoder passwordEncoder;
    private final UserService userService;
    private final UserRolesRepository userRolesRepository;
    private final AuthenticationHelper authenticationHelper;
    private final RolesRepository rolesRepository;

    @Override
    @Transactional
    public AdminRegisterResponse register(AdminRegisterRequest request, Long adminClientApplicationId) {

        if (!authenticationHelper.isAdmin()) {
            // Step 5 (TOCTOU fix): lock the create-admin Role row for the rest
            // of this transaction before checking "does an admin already
            // exist" - closes the window where two concurrent unauthenticated
            // calls could both observe "not yet" and both succeed as the
            // first admin. See RolesRepository#findByRoleNameForUpdate.
            ensureAdminRoleRowExists();
            rolesRepository.findByRoleNameForUpdate(ADMIN_ROLE);
            if (userRolesRepository.existsByRoleRoleName(ADMIN_ROLE)) {
                throw new AccessDeniedException("An admin already exists - further admin accounts must be created by an existing admin.");
            }
        }

        registrationValidator.validateUsername(request.getUsername());
        registrationValidator.validateContactInfoPresent(request.getPhoneNumber(), request.getEmail());
        registrationValidator.validatePhoneNumberIfPresent(request.getPhoneNumber());
        registrationValidator.validateEmailIfPresent(request.getEmail());
        resetValidator.validateNewPassword(request.getPassword(), request.getConfirmPassword());

        String username = request.getUsername().trim();
        if (userRepository.findByUsernameAndClientApplicationId(username, adminClientApplicationId).isPresent()) {
            throw new UserAlreadyExistsException("Username or password is incorrect");
        }

        String phoneNumber = normalize(request.getPhoneNumber());
        if (phoneNumber != null && userRepository.findByPhoneNumberAndClientApplicationId(phoneNumber, adminClientApplicationId).isPresent()) {
            throw new UserAlreadyExistsException("Phone number or password is incorrect");
        }

        String email = normalize(request.getEmail());
        if (email != null && userRepository.findByEmailAndClientApplicationId(email, adminClientApplicationId).isPresent()) {
            throw new UserAlreadyExistsException("Email or password is incorrect");
        }

        User user = new User();
        user.setClientApplicationId(adminClientApplicationId);
        user.setUsername(username);
        user.setInternalAuthUserId("IA_" + UUID.randomUUID());
        user.setPhoneNumber(phoneNumber);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setEnabled(true);
        user.setEmailVerified(email != null);
        user.setPhoneVerified(phoneNumber != null);

        User saved;
        try {
            saved = userRepository.save(user);
        } catch (DataIntegrityViolationException e) {
            log.warn("Admin registration lost a uniqueness race at save-time (username={})", username);
            throw new UserAlreadyExistsException("Unable to create account with the provided details");
        }

        BaseResponse roleAssignment = userService.addUserToAdminPermissionGroup(saved.getUsername());
        if (roleAssignment.getStatusCode() != HttpServletResponse.SC_CREATED) {
            throw PermissionException.internalError(
                    "Failed to grant admin role during admin registration: " + roleAssignment.getDescription());
        }

        log.info("New admin registered, id={}", saved.getId());

        return new AdminRegisterResponse(saved.getId(), saved.getUsername(), "Admin account created successfully.");
    }

    private String normalize(String value) {
        return (value == null || value.isBlank()) ? null : value.trim();
    }

    /**
     * Step 5 (admin bootstrap race fix): guarantees the create-admin Role
     * row exists purely so findByRoleNameForUpdate always has a row to lock
     * on, even before any admin has ever been created. Same lazy,
     * race-safe get-or-create pattern as
     * ClientApplicationService#getOrCreateInternalAdminClient - existence of
     * this row carries no authorization meaning by itself, only whether a
     * user currently holds it does.
     */
    private void ensureAdminRoleRowExists() {
        if (rolesRepository.existsByRoleName(ADMIN_ROLE)) {
            return;
        }
        Role role = new Role();
        role.setRoleName(ADMIN_ROLE);
        role.setDescription(ADMIN_ROLE_DESCRIPTION);
        role.setCreatedAt(LocalDateTime.now());
        try {
            rolesRepository.save(role);
        } catch (DataIntegrityViolationException e) {
            // Lost a create-vs-create race (V20's unique constraint on
            // role_name) - fine, the row exists now regardless of who
            // created it.
            log.debug("Admin role row creation lost a uniqueness race at save-time - role already exists");
        }
    }
}
