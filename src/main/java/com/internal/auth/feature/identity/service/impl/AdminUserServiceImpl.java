package com.internal.auth.feature.identity.service.impl;

import com.internal.auth.common.exception.UserAlreadyExistsException;
import com.internal.auth.common.exception.UserNotFoundException;
import com.internal.auth.common.reset.ResetValidator;
import com.internal.auth.feature.identity.dto.AdminCreateUserRequest;
import com.internal.auth.feature.identity.dto.AdminUpdateUserRequest;
import com.internal.auth.feature.identity.dto.PagedUsersResponse;
import com.internal.auth.feature.identity.dto.UserProfileResponse;
import com.internal.auth.feature.identity.dto.UserSummaryResponse;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.identity.service.AdminUserService;
import com.internal.auth.feature.identity.validation.RegistrationValidator;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Step 2A (React Admin Client plan v4). Reuses
 * findByUsernameAndClientApplicationId (already added for the multi-tenant
 * redesign) for the single-user lookups - same safe, scoped resolution
 * MfaAdminServiceImpl already relies on.
 */
@Service
@RequiredArgsConstructor
public class AdminUserServiceImpl implements AdminUserService {

    private final UserRepository userRepository;
    private static final Logger log = LoggerFactory.getLogger(AdminUserServiceImpl.class);
    private final RegistrationValidator registrationValidator;
    private final ResetValidator resetValidator;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional(readOnly = true)
    public PagedUsersResponse listUsers(Long clientApplicationId, String search, Boolean enabled, Pageable pageable) {
        String normalizedSearch = (search == null || search.isBlank()) ? null : search.trim();
        Page<User> page = userRepository.searchForAdmin(clientApplicationId, enabled, normalizedSearch, pageable);
        List<UserSummaryResponse> content = page.getContent().stream()
                .map(this::toSummary)
                .toList();
        return new PagedUsersResponse(content, page.getNumber(), page.getSize(), page.getTotalElements(), page.getTotalPages());
    }

    @Override
    @Transactional(readOnly = true)
    public UserProfileResponse getUserProfile(String username, Long clientApplicationId) {
        User user = userRepository.findByUsernameAndClientApplicationId(username, clientApplicationId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));
        return toProfile(user);
    }

    @Override
    @Transactional
    public UserProfileResponse updateUser(String username, Long clientApplicationId, AdminUpdateUserRequest request) {
        User user = userRepository.findByUsernameAndClientApplicationId(username, clientApplicationId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (request.getEnabled() != null) {
            user.setEnabled(request.getEnabled());
        }
        if (request.getEmailVerified() != null) {
            user.setEmailVerified(request.getEmailVerified());
        }
        if (request.getPhoneVerified() != null) {
            user.setPhoneVerified(request.getPhoneVerified());
        }

        userRepository.save(user);
        return toProfile(user);
    }

    @Override
    @Transactional
    public UserProfileResponse createUser(Long clientApplicationId, AdminCreateUserRequest request) {
        registrationValidator.validateUsername(request.getUsername());
        registrationValidator.validateContactInfoPresent(request.getPhoneNumber(), request.getEmail());
        registrationValidator.validatePhoneNumberIfPresent(request.getPhoneNumber());
        registrationValidator.validateEmailIfPresent(request.getEmail());
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
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setEnabled(true);
        // Pre-verified immediately - an admin is creating this account, same
        // rationale as AdminRegistrationServiceImpl's bootstrap flow. No
        // role/permission-group assignment here by design; use the existing
        // role/group endpoints as a deliberate separate follow-up step.
        user.setEmailVerified(email != null);
        user.setPhoneVerified(phoneNumber != null);

        User saved;
        try {
            saved = userRepository.save(user);
        } catch (DataIntegrityViolationException e) {
            log.warn("Admin user creation lost a uniqueness race at save-time (username={})", username);
            throw new UserAlreadyExistsException("Unable to create account with the provided details");
        }

        log.info("Admin-created user, id={}, clientApplicationId={}", saved.getId(), clientApplicationId);

        return toProfile(saved);
    }

    private String normalize(String value) {
        return (value == null || value.isBlank()) ? null : value.trim();
    }

    private UserSummaryResponse toSummary(User user) {
        return new UserSummaryResponse(user.getId(), user.getUsername(), user.getPhoneNumber(), user.getEmail(), user.isEnabled(), user.isMfaEnabled(), user.getCreatedAt());
    }

    private UserProfileResponse toProfile(User user) {
        return new UserProfileResponse(user.getId(), user.getUsername(), user.getPhoneNumber(), user.getEmail(), user.isEnabled(), user.isEmailVerified(), user.isPhoneVerified(), user.isMfaEnabled(), user.getCreatedAt());
    }
}
