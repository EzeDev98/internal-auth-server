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
import lombok.extern.slf4j.Slf4j;
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

/** Registers the first admin and authenticates admins. */
@Service
@Slf4j
@RequiredArgsConstructor
public class AdminRegistrationServiceImpl implements AdminRegistrationService {

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
            log.debug("Admin role row creation lost a uniqueness race at save-time - role already exists");
        }
    }
}
