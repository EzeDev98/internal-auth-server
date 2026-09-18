package com.internal.auth.feature.identity.service.impl;

import com.internal.auth.common.exception.UserAlreadyExistsException;
import com.internal.auth.common.exception.UserNotFoundException;
import com.internal.auth.common.reset.ResetValidator;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.feature.identity.dto.request.AdminCreateUserRequest;
import com.internal.auth.feature.identity.dto.request.AdminResetPasswordRequest;
import com.internal.auth.feature.identity.dto.request.AdminUpdateUserRequest;
import com.internal.auth.feature.identity.dto.response.PagedUsersResponse;
import com.internal.auth.feature.identity.dto.response.UserCredentialResponse;
import com.internal.auth.feature.identity.dto.response.UserProfileResponse;
import com.internal.auth.feature.identity.dto.response.UserSummaryResponse;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.identity.service.AdminUserService;
import com.internal.auth.feature.identity.validation.RegistrationValidator;
import com.internal.auth.feature.rbac.service.impl.EntityUtilityService;
import com.internal.auth.feature.session.service.SessionManagementService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Step 2A (React Admin Client plan v4). Reuses
 * findByUsernameAndClientApplicationId (already added for the multi-tenant
 * redesign) for the single-user lookups - same safe, scoped resolution
 * MfaAdminServiceImpl already relies on.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class AdminUserServiceImpl implements AdminUserService {

    private final UserRepository userRepository;
    private final RegistrationValidator registrationValidator;
    private final ResetValidator resetValidator;
    private final PasswordEncoder passwordEncoder;
    private final EntityUtilityService entityUtilityService;
    private final ClientApplicationService clientApplicationService;
    private final SessionManagementService sessionManagementService;

    @Override
    @Transactional(readOnly = true)
    public PagedUsersResponse listUsers(Long clientApplicationId, String search, Boolean enabled, Pageable pageable) {
        String normalizedSearch = (search == null || search.isBlank()) ? null : search.trim();
        Page<User> page = userRepository.searchForAdmin(clientApplicationId, enabled, normalizedSearch, pageable);

        // Batch-resolve every distinct clientApplicationId on this page in
        // ONE query instead of the old per-row resolveClientId() lookup -
        // see ClientApplicationService#getClientIdsByIds's javadoc for why
        // that N+1 pattern was the real cause of this endpoint timing out.
        Set<Long> clientApplicationIds = page.getContent().stream()
                .map(User::getClientApplicationId)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
        Map<Long, String> clientIdByApplicationId = clientApplicationService.getClientIdsByIds(clientApplicationIds);

        List<UserSummaryResponse> content = page.getContent().stream()
                .map(user -> toSummary(user, clientIdByApplicationId))
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
        user.setInternalAuthUserId("IA_" + UUID.randomUUID());
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

    @Override
    public void deleteUser(String internalAuthUserId, Long clientApplicationId) {
        userRepository.findByInternalAuthUserIdAndClientApplicationId(internalAuthUserId, clientApplicationId).ifPresent(user -> {
            entityUtilityService.deleteUserRoles(user);
            entityUtilityService.deleteUserGroups(user);
            userRepository.delete(user);
        });
    }

    @Override
    @Transactional(readOnly = true)
    public UserCredentialResponse getCredential(String username, Long clientApplicationId) {
        User user = userRepository.findByUsernameAndClientApplicationId(username, clientApplicationId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));
        LocalDateTime createdAt = user.getPasswordChangedAt() != null ? user.getPasswordChangedAt() : user.getCreatedAt();
        return new UserCredentialResponse("password", createdAt);
    }

    @Override
    @Transactional
    public void resetPassword(String username, Long clientApplicationId, AdminResetPasswordRequest request) {
        resetValidator.validateNewPassword(request.getNewPassword(), request.getConfirmPassword());

        User user = userRepository.findByUsernameAndClientApplicationId(username, clientApplicationId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setPasswordChangedAt(LocalDateTime.now());
        userRepository.save(user);

        // Same post-reset session invalidation PasswordResetServiceImpl#completeReset
        // performs - forces a fresh login with the new password.
        sessionManagementService.invalidateActiveSessionForUser(user.getId());

        log.info("Admin reset password for user id={}", user.getId());
    }

    private String normalize(String value) {
        return (value == null || value.isBlank()) ? null : value.trim();
    }

    // Step 7A (see UserSummaryResponse's Javadoc on the clientId field),
    // batch-resolved in listUsers() above instead of a per-row DB call - a
    // missing entry in clientIdByApplicationId (a stale/orphaned FK) just
    // resolves to null rather than throwing, same defensive intent the old
    // per-row try/catch had.
    private UserSummaryResponse toSummary(User user, Map<Long, String> clientIdByApplicationId) {
        String clientId = user.getClientApplicationId() == null ? null : clientIdByApplicationId.get(user.getClientApplicationId());
        return new UserSummaryResponse(user.getId(), user.getUsername(), user.getPhoneNumber(), user.getEmail(), user.isEnabled(), user.isMfaEnabled(), user.getCreatedAt(), clientId);
    }

    private UserProfileResponse toProfile(User user) {
        return new UserProfileResponse(user.getId(), user.getUsername(), user.getPhoneNumber(), user.getEmail(), user.isEnabled(), user.isEmailVerified(), user.isPhoneVerified(), user.isMfaEnabled(), user.getCreatedAt());
    }
}
