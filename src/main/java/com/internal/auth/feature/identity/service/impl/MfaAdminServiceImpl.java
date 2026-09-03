package com.internal.auth.feature.identity.service.impl;

import com.internal.auth.common.exception.BadRequestException;
import com.internal.auth.common.exception.UserNotFoundException;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.identity.service.MfaAdminService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Step 11E. Admin-gated for now, not self-service: local login (11A)
 * issues no token yet (Step 12), so a locally-logged-in user has no way to
 * authenticate a follow-up "enable my own MFA" call today. Reuses the same
 * already-working admin-authentication path (Keycloak-issued JWT +
 * @PreAuthorize(Roles.HAS_ADMIN)) that ClientApplicationController/
 * PermissionController already depend on. Revisit once Step 12 gives local
 * users a real session to act through.
 */
@Service
@RequiredArgsConstructor
public class MfaAdminServiceImpl implements MfaAdminService {

    private static final Logger log = LoggerFactory.getLogger(MfaAdminServiceImpl.class);

    private final UserRepository userRepository;

    @Override
    @Transactional
    public void setMfaEnabled(String username, boolean enabled) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (enabled && (user.getPhoneNumber() == null || user.getPhoneNumber().isBlank())) {
            throw new BadRequestException("Cannot enable MFA for a user with no phone number on file - the login step-up is SMS-based.");
        }

        user.setMfaEnabled(enabled);
        userRepository.save(user);
        log.info("MFA {} for user {}", enabled ? "enabled" : "disabled", username);
    }
}
